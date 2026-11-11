#!/bin/sh
# swinventory 에이전트 설치 스크립트 (Linux, root 로 실행 — 에이전트 자체는 비특권 계정으로 돈다)
#
#   sudo ./install.sh --server-url https://inventory.example.com --token-file ./ingest-token \
#        [--ca-file ca.pem] [--client-cert c.pem --client-key c.key] [--pyz swinventory-agent.pyz]
#   서버에서 내려받아 설치(화면의 "서버 등록"이 이 명령을 만들어 준다):
#        printf '%s' "$TOKEN" | sudo sh install.sh --token-stdin --server-url URL --agent-url URL/download/swinventory-agent.pyz --sha256 <해시>
#   다운로드·해시 검증만(root 불필요): sh install.sh --download-only --agent-url URL --sha256 <해시> [--out 파일]
#   sudo ./install.sh --uninstall [--purge]
#
# 하는 일: 단일 파일 에이전트 설치 → 전용 계정(swinventory) → 설정/토큰(0640) → 계정 권한으로 첫 수집 검증
#          → systemd timer 등록(systemd 가 있고 --no-systemd 가 아닐 때).  멱등: 다시 실행하면 갱신한다.
#
# 종료 코드: 0 성공 · 1 설치/수집 실패 · 2 인자 오류 · 3 설치는 끝났지만 서버에 첫 전송을 확인하지 못함(스풀 보관)
set -eu

DMI_SERIAL_FILE=/sys/class/dmi/id/product_serial
CONTAINERS=auto; HELPER_DIR=/var/lib/swinventory-helper
SERVER_URL=""; TOKEN=""; TOKEN_FILE=""; CA_FILE=""; CLIENT_CERT=""; CLIENT_KEY=""
AGENT_URL=""; SHA256=""; OUT=""; FETCHED=""; LOG=""
DOWNLOAD_ONLY=0; TOKEN_STDIN=0
PYZ=""; PYTHON=""; USER_NAME="swinventory"; INTERVAL="hourly"
NO_SYSTEMD=0; ALLOW_HTTP=0; UNINSTALL=0; PURGE=0
INSTALL_DIR=/usr/local/lib/swinventory
CONF_DIR=/etc/swinventory
STATE_DIR=/var/lib/swinventory
UNIT_DIR=/etc/systemd/system

die()  { echo "ERROR: $*" >&2; exit "${2:-1}"; }
info() { echo "==> $*"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --server-url) SERVER_URL=$2; shift 2 ;;
    --token) TOKEN=$2; shift 2 ;;                    # 인자는 ps 에 보인다 — 가능하면 --token-stdin·--token-file·SWINV_TOKEN 을 쓴다
    --token-stdin) TOKEN_STDIN=1; shift ;;
    --agent-url) AGENT_URL=$2; shift 2 ;;
    --sha256) SHA256=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    --download-only) DOWNLOAD_ONLY=1; shift ;;
    --token-file) TOKEN_FILE=$2; shift 2 ;;
    --ca-file) CA_FILE=$2; shift 2 ;;
    --client-cert) CLIENT_CERT=$2; shift 2 ;;
    --client-key) CLIENT_KEY=$2; shift 2 ;;
    --containers) CONTAINERS=on; shift ;;           # 컨테이너 헬퍼를 강제로 설치(기본 auto: crictl·docker 가 있으면)
    --no-containers) CONTAINERS=off; shift ;;
    --dmi-serial-file) DMI_SERIAL_FILE=$2; shift 2 ;;   # 장비 시리얼을 읽을 파일(기본 DMI). 펌웨어가 시리얼을 못 주는 장비·테스트용
    --pyz) PYZ=$2; shift 2 ;;
    --python) PYTHON=$2; shift 2 ;;
    --user) USER_NAME=$2; shift 2 ;;
    --interval) INTERVAL=$2; shift 2 ;;
    --no-systemd) NO_SYSTEMD=1; shift ;;
    --allow-insecure-http) ALLOW_HTTP=1; shift ;;   # 실험실 전용. 운영은 https 만
    --uninstall) UNINSTALL=1; shift ;;
    --purge) PURGE=1; shift ;;
    -h|--help) sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "알 수 없는 옵션: $1" 2 ;;
  esac
done

cleanup() { rm -f "${LOG:-}" "${FETCHED:-}"; }
trap cleanup EXIT
[ -n "$PYTHON" ] || PYTHON=$(command -v python3 || true)

# curl → wget → python3 순으로 시도한다(최소 설치 서버에는 curl/wget 이 없을 수 있다). 사설 CA 는 --ca-file.
download() { # url dest
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 2 --connect-timeout 15 ${CA_FILE:+--cacert "$CA_FILE"} -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" ${CA_FILE:+--ca-certificate="$CA_FILE"} "$1"
  elif [ -n "$PYTHON" ]; then
    "$PYTHON" - "$1" "$2" "${CA_FILE:-}" <<'PY'
import ssl, sys, urllib.request
url, dest, ca = sys.argv[1:4]
ctx = ssl.create_default_context(cafile=ca or None)
with urllib.request.urlopen(url, context=ctx, timeout=30) as response, open(dest, "wb") as out:
    out.write(response.read())
PY
  else
    return 1
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  elif [ -n "$PYTHON" ]; then "$PYTHON" -c 'import hashlib, sys; print(hashlib.sha256(open(sys.argv[1], "rb").read()).hexdigest())' "$1"
  else die "sha256 을 계산할 도구가 없다(sha256sum/shasum/python3)"
  fi
}

# 서버에서 에이전트를 내려받아 해시를 확인한다. 해시는 관리자 화면이 만든 명령에 박혀 있다 — 다르면 설치하지 않고 파일도 남기지 않는다.
fetch_agent() {
  [ -n "$SHA256" ] || die "--agent-url 에는 --sha256 이 필요하다(다운로드 무결성을 고정한다)" 2
  case "$SHA256" in *[!0-9a-fA-F]*) die "--sha256 은 16진수 64자여야 한다" 2 ;; esac
  [ "${#SHA256}" -eq 64 ] || die "--sha256 은 16진수 64자여야 한다" 2
  SHA256=$(printf '%s' "$SHA256" | tr 'A-F' 'a-f')
  case "$AGENT_URL" in
    https://*) ;;
    http://*) [ "$ALLOW_HTTP" -eq 1 ] || die "에이전트 URL 은 https 만 허용한다(실험실은 --allow-insecure-http)" 2 ;;
    *) die "--agent-url 은 http(s):// 형식이어야 한다" 2 ;;
  esac
  FETCHED=$(mktemp) || die "임시 파일을 만들지 못했다"
  download "$AGENT_URL" "$FETCHED" || { rm -f "$FETCHED"; FETCHED=""; die "에이전트를 내려받지 못했다: $AGENT_URL"; }
  actual=$(sha256_of "$FETCHED")
  if [ "$actual" != "$SHA256" ]; then
    rm -f "$FETCHED"; FETCHED=""
    die "에이전트 해시 불일치 — 설치하지 않는다 (기대 $SHA256, 실제 $actual). 서버의 파일이 바뀌었으면 화면에서 명령을 다시 만든다."
  fi
  PYZ=$FETCHED
}

if [ "$DOWNLOAD_ONLY" -eq 1 ]; then      # root·systemd 없이 다운로드와 해시 검증만(사전 배치·진단용)
  [ -n "$AGENT_URL" ] || die "--download-only 에는 --agent-url 이 필요하다" 2
  fetch_agent
  if [ -n "$OUT" ]; then mv "$FETCHED" "$OUT"; FETCHED=""; PYZ=$OUT; else FETCHED=""; fi
  echo "$PYZ"
  exit 0
fi

[ "$(id -u)" -eq 0 ] || die "root 로 실행해야 한다(설치만 root, 에이전트는 '$USER_NAME' 계정으로 실행된다)" 2
case "$USER_NAME" in ''|*[!a-z0-9_-]*) die "--user 값이 올바르지 않다" 2 ;; esac
case "$INTERVAL" in *[!A-Za-z0-9*:.,/\ -]*|'') die "--interval 에 허용되지 않는 문자가 있다" 2 ;; esac

has_systemd() { [ "$NO_SYSTEMD" -eq 0 ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

if [ "$UNINSTALL" -eq 1 ]; then
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl disable --now swinventory.timer >/dev/null 2>&1 || true
    systemctl disable --now swinventory-containers.timer >/dev/null 2>&1 || true
    rm -f "$UNIT_DIR/swinventory.service" "$UNIT_DIR/swinventory.timer" "$UNIT_DIR/swinventory-containers.service" "$UNIT_DIR/swinventory-containers.timer"
    systemctl daemon-reload || true
  fi
  rm -rf "$INSTALL_DIR" "$HELPER_DIR"
  if [ "$PURGE" -eq 1 ]; then
    rm -rf "$CONF_DIR" "$STATE_DIR"
    id -u "$USER_NAME" >/dev/null 2>&1 && userdel "$USER_NAME" 2>/dev/null || true
  fi
  info "제거 완료$([ "$PURGE" -eq 1 ] && echo ' (설정·스풀·계정 포함)' || echo ' (설정과 스풀은 남겼다: --purge 로 삭제)')"
  exit 0
fi

[ -n "$SERVER_URL" ] || die "--server-url 이 필요하다" 2
case "$SERVER_URL" in
  https://*) ;;
  http://*) [ "$ALLOW_HTTP" -eq 1 ] || die "https 만 허용한다(실험실은 --allow-insecure-http)" 2 ;;
  *) die "--server-url 은 https://… 형식이어야 한다" 2 ;;
esac
if [ "$TOKEN_STDIN" -eq 1 ]; then TOKEN=$(cat); fi                      # printf 는 셸 내장이라 ps 에 토큰이 남지 않는다
[ -n "$TOKEN" ] || [ -n "$TOKEN_FILE" ] || TOKEN=${SWINV_TOKEN:-}
unset SWINV_TOKEN                                                       # 하위 프로세스(첫 수집 검증)로 새지 않게
[ -n "$TOKEN" ] || [ -n "$TOKEN_FILE" ] || die "토큰이 필요하다: --token-stdin(권장)·--token-file·SWINV_TOKEN 환경변수·--token" 2
[ -z "$TOKEN_FILE" ] || [ -r "$TOKEN_FILE" ] || die "--token-file 을 읽을 수 없다: $TOKEN_FILE" 2
[ -z "$CLIENT_CERT" ] || [ -n "$CLIENT_KEY" ] || die "--client-cert 는 --client-key 와 함께 지정한다" 2

# --- python3 (3.9+) ---------------------------------------------------------
[ -n "$PYTHON" ] || PYTHON=$(command -v python3 || true)
[ -n "$PYTHON" ] || die "python3 를 찾지 못했다(3.9 이상 필요). 예) dnf install python3 / apt-get install python3"
"$PYTHON" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' \
  || die "$PYTHON 는 $("$PYTHON" -c 'import sys; print("%d.%d" % sys.version_info[:2])') — 3.9 이상이 필요하다(--python 으로 다른 인터프리터 지정)"

# IP·MAC 수집은 iproute2 의 `ip -j` 를 쓴다(열린 포트는 /proc 을 직접 읽어 도구가 필요 없다)
command -v ip >/dev/null 2>&1 || echo "WARN: 'ip' 명령(iproute2)이 없어 IP·MAC 수집(network.interfaces)이 실패한다. 설치: apt-get install iproute2 / dnf install iproute" >&2

# --- 에이전트 파일 ----------------------------------------------------------
if [ -n "$AGENT_URL" ]; then
  [ -z "$PYZ" ] || die "--pyz 와 --agent-url 은 함께 쓸 수 없다" 2
  info "에이전트 다운로드: $AGENT_URL"
  fetch_agent
  info "sha256 일치 확인"
fi
if [ -z "$PYZ" ]; then
  here=$(cd "$(dirname "$0")" && pwd)
  for c in "$here/swinventory-agent.pyz" "$here/../../dist/swinventory-agent.pyz" ./swinventory-agent.pyz; do
    [ -f "$c" ] && PYZ=$c && break
  done
fi
[ -n "$PYZ" ] && [ -f "$PYZ" ] || die "swinventory-agent.pyz 를 찾지 못했다(--pyz 로 지정, 빌드: python3 scripts/build_agent.py)"

info "에이전트 설치: $INSTALL_DIR/swinventory-agent.pyz"
install -d -m 0755 "$INSTALL_DIR"
install -m 0755 "$PYZ" "$INSTALL_DIR/swinventory-agent.pyz"

# --- 전용 계정·디렉터리 -----------------------------------------------------
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
  NOLOGIN=$(command -v nologin || echo /sbin/nologin)
  info "계정 생성: $USER_NAME (시스템 계정, 로그인 불가)"
  useradd --system --no-create-home --home-dir "$STATE_DIR" --shell "$NOLOGIN" "$USER_NAME"
fi
install -d -m 0750 -o root -g "$USER_NAME" "$CONF_DIR"
install -d -m 0750 -o "$USER_NAME" -g "$USER_NAME" "$STATE_DIR"

# --- 토큰·인증서(소유자 root, 그룹 읽기 전용) --------------------------------
if [ -n "$TOKEN_FILE" ]; then
  install -m 0640 -o root -g "$USER_NAME" "$TOKEN_FILE" "$CONF_DIR/token"
else
  ( umask 077; printf '%s\n' "$TOKEN" > "$CONF_DIR/token" )
  chown root:"$USER_NAME" "$CONF_DIR/token"; chmod 0640 "$CONF_DIR/token"
fi
# DMI 시리얼(product_serial)은 커널이 root 만 읽게 노출한다 — 에이전트는 비특권이라 설치(root) 때 한 번 읽어 둔다. 못 읽으면 건너뛴다(자산 대장의 시리얼로 보완).
if SERIAL=$(head -n 1 "$DMI_SERIAL_FILE" 2>/dev/null) && [ -n "$SERIAL" ]; then
  ( umask 027; printf '%s\n' "$SERIAL" > "$CONF_DIR/dmi_serial" )
  chown root:"$USER_NAME" "$CONF_DIR/dmi_serial"; chmod 0640 "$CONF_DIR/dmi_serial"
else
  rm -f "$CONF_DIR/dmi_serial"
fi
[ -z "$CA_FILE" ] || install -m 0644 -o root -g "$USER_NAME" "$CA_FILE" "$CONF_DIR/ca.pem"
[ -z "$CLIENT_CERT" ] || install -m 0640 -o root -g "$USER_NAME" "$CLIENT_CERT" "$CONF_DIR/client.pem"
[ -z "$CLIENT_KEY" ] || install -m 0640 -o root -g "$USER_NAME" "$CLIENT_KEY" "$CONF_DIR/client.key"

# JSON 은 문자열 이스케이프를 파이썬에 맡긴다(경로·URL 에 특수문자가 있어도 안전)
SWINV_URL=$SERVER_URL SWINV_CONF=$CONF_DIR SWINV_STATE=$STATE_DIR SWINV_HTTP=$ALLOW_HTTP \
SWINV_HAS_CA=$([ -n "$CA_FILE" ] && echo 1 || echo 0) SWINV_HAS_CERT=$([ -n "$CLIENT_CERT" ] && echo 1 || echo 0) \
"$PYTHON" - <<'PY'
import json, os
e, conf = os.environ, os.environ["SWINV_CONF"]
cfg = {"server_url": e["SWINV_URL"], "token_file": f"{conf}/token", "spool_path": f"{e['SWINV_STATE']}/spool.db"}
if e["SWINV_HAS_CA"] == "1":
    cfg["ca_file"] = f"{conf}/ca.pem"
if e["SWINV_HAS_CERT"] == "1":
    cfg.update(client_cert=f"{conf}/client.pem", client_key=f"{conf}/client.key")
if e["SWINV_HTTP"] == "1":
    cfg["allow_insecure_http"] = True
with open(f"{conf}/agent.json", "w", encoding="utf-8") as f:
    json.dump(cfg, f, indent=2); f.write("\n")
PY
chown root:"$USER_NAME" "$CONF_DIR/agent.json"; chmod 0640 "$CONF_DIR/agent.json"

# --- 컨테이너 헬퍼(root·읽기 전용 조회) ---------------------------------------
# 컨테이너 런타임 소켓은 root 만 쓸 수 있고 에이전트는 root 가 아니다. 고정 조회 명령만 실행하는 작은 헬퍼를 root 로 돌려 원본 출력을 $HELPER_DIR 에 쓰고,
# 에이전트(비특권)가 그 파일을 읽어 해석한다. 헬퍼는 해시로 고정된 에이전트 .pyz 안에 들어 있어 별도로 내려받지 않는다.
want_containers() {
  case "$CONTAINERS" in on) return 0 ;; off) return 1 ;; esac
  command -v crictl >/dev/null 2>&1 && return 0
  command -v docker >/dev/null 2>&1 && [ -S /var/run/docker.sock ] && return 0
  return 1
}
if want_containers; then
  info "컨테이너 헬퍼 설치(root·읽기 전용 조회 → $HELPER_DIR)"
  "$PYTHON" -c 'import sys, zipfile; sys.stdout.buffer.write(zipfile.ZipFile(sys.argv[1]).read("swinventory/agent/containers-helper.sh"))' \
    "$INSTALL_DIR/swinventory-agent.pyz" > "$INSTALL_DIR/containers-helper.sh" || die "에이전트 .pyz 에서 컨테이너 헬퍼를 꺼내지 못했다(에이전트 0.3 이상 필요)"
  chown root:root "$INSTALL_DIR/containers-helper.sh"; chmod 0755 "$INSTALL_DIR/containers-helper.sh"
  install -d -m 2750 -o root -g "$USER_NAME" "$HELPER_DIR"       # setgid: 헬퍼가 만드는 파일이 에이전트 그룹으로 읽힌다
  /bin/sh "$INSTALL_DIR/containers-helper.sh" "$HELPER_DIR" || echo "WARN: 컨테이너 헬퍼 첫 실행이 실패했다(다음 주기에 다시 시도)" >&2
  if has_systemd; then
    cat > "$UNIT_DIR/swinventory-containers.service" <<UNIT
[Unit]
Description=swinventory 컨테이너 헬퍼 (root·읽기 전용 조회)

[Service]
Type=oneshot
ExecStart=/bin/sh $INSTALL_DIR/containers-helper.sh $HELPER_DIR
TimeoutStartSec=120
Nice=10
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=$HELPER_DIR
RestrictAddressFamilies=AF_UNIX
ProtectKernelModules=true
ProtectControlGroups=true
UNIT
    cat > "$UNIT_DIR/swinventory-containers.timer" <<UNIT
[Unit]
Description=swinventory 컨테이너 헬퍼 주기 실행

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min

[Install]
WantedBy=timers.target
UNIT
    systemctl daemon-reload
    systemctl enable --now swinventory-containers.timer
  fi
else
  # 런타임이 사라졌거나 --no-containers: 옛 헬퍼 결과가 남아 '현재 상태'처럼 읽히지 않게 치운다
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl disable --now swinventory-containers.timer >/dev/null 2>&1 || true
    rm -f "$UNIT_DIR/swinventory-containers.service" "$UNIT_DIR/swinventory-containers.timer"
  fi
  rm -rf "$HELPER_DIR" "$INSTALL_DIR/containers-helper.sh"
fi

# --- systemd ----------------------------------------------------------------
if has_systemd; then
  info "systemd timer 등록 ($INTERVAL)"
  cat > "$UNIT_DIR/swinventory.service" <<UNIT
[Unit]
Description=swinventory agent (설치 소프트웨어·커널 수집)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=$USER_NAME
ExecStart=$PYTHON $INSTALL_DIR/swinventory-agent.pyz collect --config $CONF_DIR/agent.json
TimeoutStartSec=300
Nice=10
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ProtectKernelModules=true
ProtectControlGroups=true
UNIT
  cat > "$UNIT_DIR/swinventory.timer" <<UNIT
[Unit]
Description=swinventory agent 주기 실행

[Timer]
OnCalendar=$INTERVAL
RandomizedDelaySec=10min
Persistent=true

[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now swinventory.timer
elif [ "$NO_SYSTEMD" -eq 0 ]; then
  echo "NOTE: systemd 를 찾지 못했다. cron 등으로 다음을 주기 실행하라:" >&2
  echo "      $PYTHON $INSTALL_DIR/swinventory-agent.pyz collect --config $CONF_DIR/agent.json  (실행 계정: $USER_NAME)" >&2
fi

# --- 비특권 계정으로 첫 수집 검증 ---------------------------------------------
info "첫 수집 검증 ($USER_NAME 계정, root 아님)"
LOG=$(mktemp)
rc=0
if command -v runuser >/dev/null 2>&1; then
  runuser -u "$USER_NAME" -- "$PYTHON" "$INSTALL_DIR/swinventory-agent.pyz" collect --config "$CONF_DIR/agent.json" 2>"$LOG" || rc=$?
else
  su -s /bin/sh "$USER_NAME" -c "exec '$PYTHON' '$INSTALL_DIR/swinventory-agent.pyz' collect --config '$CONF_DIR/agent.json'" 2>"$LOG" || rc=$?
fi
cat "$LOG"
[ "$rc" -eq 0 ] || die "첫 수집이 실패했다(종료 코드 $rc). 위 로그를 확인한다. 설치 파일은 배치됐다." 1
if grep -q '스풀에 보관' "$LOG"; then
  die "설치는 끝났지만 서버에 전송하지 못해 스풀에 보관됐다 — 서버 주소·토큰·방화벽·CA 를 확인한다. (복구 후 자동 재전송됨)" 3
fi
info "설치 완료. 서버에 첫 스냅샷을 전달했다."
