#!/bin/bash
# 실제 환경 종단 검증: 서버+PostgreSQL(compose) ← 실제 Linux 컨테이너 3종의 에이전트(install.sh, 비특권 계정)
#   1) 설치·첫 수집(기준선)  2) 패키지를 실제로 설치/제거한 뒤 재수집 → 변경 이벤트  3) 서버 장애 시 스풀 → 복구 후 재전송
# 사용: scripts/e2e_docker.sh      (docker 필요. 프로젝트명 swinv-e2e 로 격리하며 끝나면 모두 정리한다)
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PY:-.venv/bin/python}
P=swinv-e2e
export WITH_WINDOWS=${E2E_WINDOWS:-0}   # 1 이면 서버 이미지에 Windows exe 도 빌드해 넣고 배포 파일을 검증한다(느림)
export POSTGRES_PASSWORD=e2e-pg-pass SWINV_INGEST_TOKENS=e2e-ingest SWINV_READ_TOKENS=e2e-read SWINV_ADMIN_TOKENS=e2e-admin
export SWINV_PORT=$($PY -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
API=http://127.0.0.1:$SWINV_PORT
fail=0
pass() { echo "PASS $*"; }
bad()  { echo "FAIL $*"; fail=1; }
get()  { curl -fsS -H "Authorization: Bearer e2e-read" "$API$1"; }
jq_()  { $PY -c "import sys,json; d=json.load(sys.stdin); print($1)"; }

cleanup() {
  docker rm -f swinv-e2e-ubuntu swinv-e2e-debian swinv-e2e-rocky swinv-e2e-llm swinv-e2e-extra swinv-e2e-dockercli >/dev/null 2>&1 || true
  rm -f /tmp/swinv-e2e-docker-cli
  docker compose -p $P down -v --rmi local >/dev/null 2>&1 || true
}
trap cleanup EXIT

$PY scripts/build_agent.py
# 컨테이너 헬퍼 검증용: 호스트의 도커 소켓 + 도커 CLI(정적 바이너리)를 테스트 컨테이너에 넣는다(헬퍼가 root 로 실제 docker ps 를 실행한다)
docker rm -f swinv-e2e-dockercli >/dev/null 2>&1 || true
docker create --name swinv-e2e-dockercli docker:cli >/dev/null && docker cp swinv-e2e-dockercli:/usr/local/bin/docker /tmp/swinv-e2e-docker-cli && docker rm swinv-e2e-dockercli >/dev/null
docker compose -p $P up -d --build >/dev/null 2>&1
for i in $(seq 1 60); do curl -fsS $API/healthz >/dev/null 2>&1 && break; sleep 1; done
curl -fsS $API/healthz >/dev/null && pass "서버+PostgreSQL 기동·헬스체크" || { bad "서버 기동 실패"; docker compose -p $P logs server | tail -20; exit 1; }
NET=${P}_default

# 컨테이너는 시스템 python3 로 에이전트를 돌린다(우분투 22.04=3.10, 데비안 12=3.11, 로키 9=3.9)
start() { # name image install-cmd
  docker run -d --name "swinv-e2e-$1" --hostname "e2e-$1" --network $NET -v "$PWD/dist/swinventory-agent.pyz:/opt/a.pyz:ro" -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$PWD/deploy/agent/install.sh:/opt/install.sh:ro" "$2" sleep 3600 >/dev/null
  docker exec "swinv-e2e-$1" sh -c "$3 && cat /proc/sys/kernel/random/uuid | tr -d - > /etc/machine-id" >/dev/null 2>&1
  docker cp /tmp/swinv-e2e-docker-cli "swinv-e2e-$1:/usr/local/bin/docker"
}
start ubuntu ubuntu:22.04 'apt-get update -qq && apt-get install -y -qq python3 util-linux passwd bc iproute2 curl sudo'
start debian debian:12 'apt-get update -qq && apt-get install -y -qq python3 util-linux passwd iproute2 curl sudo'
start rocky rockylinux:9 'dnf install -y -q python3 shadow-utils util-linux iproute sudo'

# 실제 리스너를 띄워 둔 상태에서 기준선을 수집한다(컨테이너 안의 진짜 소켓 → /proc/net → 에이전트 → 서버)
listen() { docker exec -d "swinv-e2e-$1" sh -c "echo \$\$ > /tmp/l$2.pid; exec python3 -m http.server $2 --bind $3" >/dev/null; }
for n in ubuntu debian rocky; do listen $n 8080 0.0.0.0; done
listen ubuntu 7070 127.0.0.1
docker exec -d swinv-e2e-rocky python3 -c "import socket,time; s=socket.socket(); s.bind(('0.0.0.0',6379)); s.listen(); time.sleep(3600)"
sleep 2

# --- 서버 등록: 서버가 만든 설치 명령(서버에서 에이전트를 내려받고 sha256 을 확인)을 그대로 실행한다 ---
adm() { curl -fsS -H "Authorization: Bearer e2e-admin" "$@"; }
enroll_cmd() { adm -G --data-urlencode "base_url=http://server:8000" "$@" "$API/v1/enrollment" | jq_ "d['commands']['linux']"; }
masked=$(adm -G --data-urlencode "base_url=http://server:8000" "$API/v1/enrollment" | jq_ "d['commands']['linux']")
case "$masked" in *e2e-ingest*) bad "토큰 미포함 명령에 토큰이 들어 있다" ;; *) pass "토큰 미포함 명령에는 토큰이 없다(자리표시자)" ;; esac
CMD=$(enroll_cmd -d include_token=true)
case "$CMD" in *"printf '%s' e2e-ingest |"*) pass "토큰 포함 명령은 토큰을 표준입력으로 넘긴다(ps 에 인자로 남지 않음)" ;; *) bad "토큰 전달 방식: $CMD" ;; esac
adm "$API/v1/enrollment?base_url=http%3A%2F%2Fserver%3A8000" | jq_ "d['agents']['linux']['sha256']" | grep -qE '^[0-9a-f]{64}$' && pass "서버가 에이전트의 sha256 을 제공" || bad "sha256"
docker exec swinv-e2e-ubuntu sh -c 'curl -fsS http://server:8000/download/SHA256SUMS' | grep -q 'swinventory-agent.pyz' && pass "에이전트 배포 파일이 서버에서 내려옴(무인증)" || bad "배포 파일"

# 변조 방어: 해시가 다르면 설치하지 않는다(ubuntu 에서 먼저 시도하고 아무것도 설치되지 않았는지 확인)
BAD=$(printf '%s' "$CMD" | sed -E 's/--sha256 [0-9a-f]{64}/--sha256 0000000000000000000000000000000000000000000000000000000000000000/')
if docker exec swinv-e2e-ubuntu bash -c "$BAD" >/tmp/swinv-e2e-badhash.log 2>&1; then bad "해시가 틀린데 설치가 성공했다"; else
  grep -q "해시 불일치" /tmp/swinv-e2e-badhash.log && ! docker exec swinv-e2e-ubuntu test -e /usr/local/lib/swinventory && pass "해시 불일치 → 설치 중단, 아무것도 설치되지 않음" || { bad "해시 불일치 처리"; cat /tmp/swinv-e2e-badhash.log; }
fi

# 컨테이너(Docker Desktop VM)에는 읽을 수 있는 DMI 시리얼이 없다 — 설치 스크립트의 시리얼 저장과 에이전트의 읽기 경로를 끝까지 검증하려고 가짜 시리얼 파일을 지정한다
for n in ubuntu debian rocky; do docker exec swinv-e2e-$n sh -c "printf 'E2E-SN-$n\n' > /tmp/e2e_serial"; done
install() { # name — ubuntu·debian 은 서버가 만든 명령으로, rocky 는 마운트한 파일(--pyz)로 설치해 두 경로를 모두 확인한다
  if [ "$1" = rocky ]; then
    docker exec "swinv-e2e-$1" sh /opt/install.sh --server-url http://server:8000 --allow-insecure-http \
      --token e2e-ingest --pyz /opt/a.pyz --no-systemd --dmi-serial-file /tmp/e2e_serial 2>&1 | sed "s/^/  [$1] /"
  else
    docker exec "swinv-e2e-$1" bash -c "$CMD --dmi-serial-file /tmp/e2e_serial" 2>&1 | sed "s/^/  [$1] /"
  fi
}
for n in ubuntu debian rocky; do
  if install $n >/tmp/swinv-e2e-$n.log 2>&1; then pass "[$n] 설치 + 비특권 계정 첫 수집$([ $n = rocky ] && echo ' (--pyz 경로)' || echo ' (서버가 만든 한 줄 명령)')"; else bad "[$n] 설치 실패"; cat /tmp/swinv-e2e-$n.log; fi
done
grep -q "sha256 일치 확인" /tmp/swinv-e2e-ubuntu.log && pass "[ubuntu] 내려받은 에이전트의 sha256 일치를 확인하고 설치" || bad "sha256 확인 로그 없음"

hosts=$(get /v1/hosts | jq_ "len(d)")
[ "$hosts" = "3" ] && pass "서버에 호스트 3대 등록(기준선)" || bad "호스트 수 $hosts (3 기대)"
ev0=$(get /v1/events | jq_ "len(d)")
[ "$ev0" = "0" ] && pass "첫 스냅샷은 기준선 — 이벤트 0건" || bad "기준선인데 이벤트 $ev0 건"
get /v1/hosts | jq_ "'; '.join(f\"{h['hostname']}: {h['os_name']} / kernel {h['running']} / {h['status']}\" for h in d)"
hid() { get /v1/hosts | $PY -c "import sys,json; print([h for h in json.load(sys.stdin) if h['hostname']=='$1'][0]['host_id'])"; }
for n in ubuntu debian rocky; do
  echo "  [$n] 패키지 수 / 수집 오류: $(get /v1/hosts/$(hid e2e-$n) | jq_ "(len(d['packages']), d['host']['last_errors'])")"
done


# --- 네트워크: 에이전트가 보고한 IP·MAC·포트를 Docker 가 아는 값과 대조 ---
for n in ubuntu debian rocky; do
  want=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}} {{(index .NetworkSettings.Networks \"$NET\").MacAddress}}" swinv-e2e-$n)
  got=$(get /v1/hosts/$(hid e2e-$n) | jq_ "[i['addresses'][0].split('/')[0] + ' ' + i['mac'] for i in d['interfaces'] if i['name']=='eth0'][0]")
  [ "$want" = "$got" ] && pass "[$n] 에이전트가 보고한 IP·MAC 이 Docker 가 아는 값과 일치($got)" || bad "[$n] IP·MAC 불일치: docker=$want agent=$got"
done
ubuntu_ip=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" swinv-e2e-ubuntu)
[ "$(get "/v1/network/ips?q=$ubuntu_ip" | jq_ "[r['hostname'] for r in d]")" = "['e2e-ubuntu']" ] && pass "IP 로 호스트 찾기($ubuntu_ip → e2e-ubuntu)" || bad "IP 검색"
ports=$(get /v1/hosts/$(hid e2e-ubuntu) | jq_ "sorted((p['proto'],p['port'],p['bind']) for p in d['ports'] if p['port'] in (8080,7070))")
[ "$ports" = "[('tcp', 7070, '127.0.0.1'), ('tcp', 8080, '0.0.0.0')]" ] && pass "[ubuntu] 실제 리스너 수집: 8080 전체 바인딩, 7070 루프백 전용" || bad "[ubuntu] 포트: $ports"
for n in debian rocky; do
  get /v1/hosts/$(hid e2e-$n) | jq_ "any(p['port']==8080 and p['bind']=='0.0.0.0' for p in d['ports'])" | grep -q True && pass "[$n] 리스너 8080 수집" || bad "[$n] 8080 미수집"
done
nr=$(get "/v1/network/listening?notable=true" | jq_ "[(r['hostname'], r['port'], r['service']) for r in d]")
[ "$nr" = "[('e2e-rocky', 6379, 'redis')]" ] && pass "주의 포트: 전체 바인딩한 redis(6379)가 rocky 호스트로 식별됨" || bad "주의 포트: $nr"
[ "$(get /v1/overview | jq_ "d['notable_exposed_host_count']")" = "1" ] && pass "개요: 주의 포트 노출 호스트 1대" || bad "개요 지표"
[ "$(get /v1/events | jq_ "len([e for e in d if e['event_type'] in ('port_opened','port_closed','ip_added','ip_removed','mac_changed')])")" = "0" ] && pass "네트워크 기준선은 이벤트 0건" || bad "네트워크 기준선에 이벤트 발생"

# --- 장비 정보: 실제 컨테이너에서 수집한 값 ---
for n in ubuntu debian rocky; do
  hwj=$(get /v1/hosts/$(hid e2e-$n) | jq_ "d['hardware']")
  [ "$hwj" != "None" ] && pass "[$n] 장비 정보 수집됨(hardware 수집기 성공)" || bad "[$n] 장비 정보 없음"
  # 컨테이너는 호스트 DMI 를 그대로 읽는다 — systemd-detect-virt 가 없는 최소 이미지여도 표식 파일로 'container' 로 판정돼야 한다
  [ "$(get /v1/hosts/$(hid e2e-$n) | jq_ "d['hardware']['kind'] + '/' + d['hardware']['virt']")" = "container/docker" ] \
    && pass "[$n] 컨테이너로 판정(물리·VM 으로 오판하지 않음)" || bad "[$n] 구분: $(get /v1/hosts/$(hid e2e-$n) | jq_ "d['hardware']")"
  # 시리얼: 설치 스크립트(root)가 읽어 저장한 값을 비특권 에이전트가 보고해야 한다
  [ "$(get /v1/hosts/$(hid e2e-$n) | jq_ "d['hardware']['serial']")" = "E2E-SN-$n" ] && pass "[$n] 설치 때 저장한 시리얼을 비특권 에이전트가 보고" || bad "[$n] 시리얼: $(get /v1/hosts/$(hid e2e-$n) | jq_ "d['hardware']")"
  [ "$(docker exec swinv-e2e-$n stat -c '%a %U:%G' /etc/swinventory/dmi_serial)" = "640 root:swinventory" ] && pass "[$n] 저장된 시리얼 파일 권한 640 root:swinventory" || bad "[$n] dmi_serial 권한"
done

# --- 컨테이너: root 헬퍼가 실제 docker 를 읽고, 비특권 에이전트가 그 결과를 보고한다 ---
declare -A IMG=([ubuntu]=ubuntu:22.04 [debian]=debian:12 [rocky]=rockylinux:9)
for n in ubuntu debian rocky; do
  row=$(get /v1/hosts/$(hid e2e-$n) | jq_ "[(c['runtime'], c['state'], c['image']) for c in d['containers'] if c['name']=='swinv-e2e-$n']")
  [ "$row" = "[('docker', 'running', '${IMG[$n]}')]" ] && pass "[$n] 실제 도커 컨테이너(자기 자신)를 수집: ${IMG[$n]} running" || bad "[$n] 컨테이너 수집: $row"
  [ "$(get /v1/hosts/$(hid e2e-$n) | jq_ "d['k8s']")" = "None" ] && pass "[$n] 쿠버네티스 노드로 오인하지 않음" || bad "[$n] k8s 오인"
  [ "$(docker exec swinv-e2e-$n stat -c '%a %U:%G' /var/lib/swinventory-helper)" = "2750 root:swinventory" ] && pass "[$n] 헬퍼 결과 디렉터리 2750 root:swinventory" || bad "[$n] 헬퍼 디렉터리 권한"
  [ "$(docker exec swinv-e2e-$n stat -c '%a %U:%G' /var/lib/swinventory-helper/docker_ps.jsonl)" = "640 root:swinventory" ] && pass "[$n] 헬퍼 결과 파일 640 root:swinventory" || bad "[$n] 헬퍼 파일 권한"
  [ "$(docker exec swinv-e2e-$n stat -c '%a %U' /usr/local/lib/swinventory/containers-helper.sh)" = "755 root" ] && pass "[$n] 헬퍼 스크립트는 root 소유 755(에이전트가 고칠 수 없음)" || bad "[$n] 헬퍼 스크립트 권한"
  if docker exec swinv-e2e-$n runuser -u swinventory -- sh -c 'touch /var/lib/swinventory-helper/forged' >/dev/null 2>&1; then bad "[$n] 에이전트 계정이 헬퍼 결과 디렉터리에 쓸 수 있다"; else pass "[$n] 에이전트 계정은 헬퍼 결과를 위조할 수 없다(쓰기 거부)"; fi
  if docker exec swinv-e2e-$n runuser -u swinventory -- docker ps >/dev/null 2>&1; then bad "[$n] 에이전트 계정이 도커 소켓을 직접 쓸 수 있다"; else pass "[$n] 에이전트 계정은 도커 소켓을 직접 쓸 수 없다(root 헬퍼만 읽음)"; fi
done
# 같은 도커 데몬을 보는 세 호스트가 새 컨테이너를 만들면, 헬퍼 재실행 → 재수집 뒤 이미지 추가 이벤트로 기록된다
docker rm -f swinv-e2e-extra >/dev/null 2>&1; docker run -d --name swinv-e2e-extra alpine:3.20 sleep 600 >/dev/null
for n in ubuntu debian rocky; do docker exec swinv-e2e-$n sh /usr/local/lib/swinventory/containers-helper.sh /var/lib/swinventory-helper; done

# 실제 패키지 변경 → 재수집 → 이벤트
docker exec swinv-e2e-ubuntu sh -c 'apt-get install -y -qq htop >/dev/null 2>&1 && apt-get remove -y -qq bc >/dev/null 2>&1'
# 포트 변경: ubuntu 에서 8080 을 닫고 9091 을 연다
docker exec swinv-e2e-ubuntu sh -c 'kill $(cat /tmp/l8080.pid)'
listen ubuntu 9091 0.0.0.0
sleep 2
docker exec swinv-e2e-debian sh -c 'apt-get install -y -qq tree >/dev/null 2>&1'
docker exec swinv-e2e-rocky sh -c 'dnf install -y -q tree >/dev/null 2>&1'
sleep 1
for n in ubuntu debian rocky; do
  docker exec swinv-e2e-$n runuser -u swinventory -- python3 /usr/local/lib/swinventory/swinventory-agent.pyz collect --config /etc/swinventory/agent.json >/dev/null 2>&1 \
    && pass "[$n] 재수집" || bad "[$n] 재수집 실패"
done
get "/v1/events?limit=100" | jq_ "'\n'.join(f\"  {e['hostname']}: {e['event_type']} {e['subject_key']} {e['old_value']}->{e['new_value']}\" for e in d)"
inst=$(get "/v1/events?type=package_installed" | jq_ "sorted(e['hostname']+':'+e['subject_key'] for e in d)")
missing=$(echo "$inst" | $PY -c "import sys,ast; want={'e2e-debian:tree','e2e-rocky:tree','e2e-ubuntu:htop'}; print(sorted(want-set(ast.literal_eval(sys.stdin.read()))))")
[ "$missing" = "[]" ] && pass "실제 설치한 패키지(tree x2, htop)가 package_installed 로 기록됨(의존 패키지 추가분 포함)" || bad "설치 이벤트 누락: $missing / 실제: $inst"
echo "  설치 이벤트 전체: $inst"
rem=$(get "/v1/events?type=package_removed" | jq_ "sorted(e['hostname']+':'+e['subject_key'] for e in d)")
[ "$rem" = "['e2e-ubuntu:bc']" ] && pass "실제 제거한 패키지(bc)가 package_removed 로 기록됨" || bad "제거 이벤트 불일치: $rem"
po=$(get "/v1/events?type=port_opened" | jq_ "sorted((e['hostname'], e['subject_key'], e['new_value']) for e in d)")
pc=$(get "/v1/events?type=port_closed" | jq_ "sorted((e['hostname'], e['subject_key'], e['old_value']) for e in d)")
[ "$po" = "[('e2e-ubuntu', 'tcp/9091', '0.0.0.0')]" ] && pass "실제로 연 포트(9091)만 port_opened 로 기록됨" || bad "port_opened: $po"
[ "$pc" = "[('e2e-ubuntu', 'tcp/8080', '0.0.0.0')]" ] && pass "실제로 닫은 포트(8080)만 port_closed 로 기록됨" || bad "port_closed: $pc"
[ "$(get /v1/events | jq_ "len([e for e in d if e['event_type'] in ('ip_added','ip_removed','mac_changed')])")" = "0" ] && pass "IP·MAC 이 그대로면 변경 이벤트 없음(안정)" || bad "IP·MAC 변경 이벤트가 생김"
kc=$(get "/v1/events?type=kernel_changed" | jq_ "len(d)")
[ "$kc" = "0" ] && pass "커널이 안 바뀌었으니 kernel_changed 0건" || bad "kernel_changed $kc"
ci=$(get "/v1/events?type=container_image_added" | jq_ "sorted((e['hostname'], e['subject_key'], e['new_value']) for e in d)")
[ "$ci" = "[('e2e-debian', 'alpine', '3.20'), ('e2e-rocky', 'alpine', '3.20'), ('e2e-ubuntu', 'alpine', '3.20')]" ] && pass "새로 띄운 컨테이너의 이미지(alpine:3.20)가 container_image_added 로 기록됨" || bad "container_image_added: $ci"
[ "$(get "/v1/images" | jq_ "[t['tag'] for i in d if i['repo']=='alpine' for t in i['tags']]")" = "['3.20']" ] && pass "이미지 분포에 alpine:3.20 이 나타남" || bad "이미지 분포"
get "/v1/software/tree" | jq_ "len(d['hosts'])" | grep -q '^2$' && pass "소프트웨어 상세: tree 설치 호스트 2대" || bad "tree 호스트 수"

# 서버 장애 → 스풀 → 복구 후 자동 재전송
docker compose -p $P stop server >/dev/null 2>&1
rc=0; docker exec swinv-e2e-ubuntu runuser -u swinventory -- python3 /usr/local/lib/swinventory/swinventory-agent.pyz collect --config /etc/swinventory/agent.json >/tmp/swinv-e2e-down.log 2>&1 || rc=$?
grep -q "스풀에 보관" /tmp/swinv-e2e-down.log && [ $rc -eq 0 ] && pass "서버 다운: 에이전트가 스풀에 보관하고 종료 코드 0" || { bad "서버 다운 처리 (rc=$rc)"; cat /tmp/swinv-e2e-down.log; }
spooled=$(docker exec swinv-e2e-ubuntu python3 -c "import sqlite3; print(sqlite3.connect('/var/lib/swinventory/spool.db').execute('select count(*) from spool').fetchone()[0])")
[ "$spooled" = "1" ] && pass "스풀 DB 에 1건 보관" || bad "스풀 $spooled 건"
docker exec swinv-e2e-ubuntu sh -c 'apt-get install -y -qq jq >/dev/null 2>&1'
docker compose -p $P start server >/dev/null 2>&1
for i in $(seq 1 40); do curl -fsS $API/healthz >/dev/null 2>&1 && break; sleep 1; done
docker exec swinv-e2e-ubuntu runuser -u swinventory -- python3 /usr/local/lib/swinventory/swinventory-agent.pyz collect --config /etc/swinventory/agent.json >/dev/null 2>&1 \
  && pass "서버 복구 후 재수집" || bad "복구 후 재수집 실패"
spooled=$(docker exec swinv-e2e-ubuntu python3 -c "import sqlite3; print(sqlite3.connect('/var/lib/swinventory/spool.db').execute('select count(*) from spool').fetchone()[0])")
[ "$spooled" = "0" ] && pass "복구 후 스풀이 비워짐(오래된 순 재전송)" || bad "스풀 잔여 $spooled 건"
get "/v1/events?type=package_installed&host=$(hid e2e-ubuntu)" \
  | jq_ "sorted(e['subject_key'] for e in d)" | grep -q "jq" && pass "스풀됐던 스냅샷의 변경(jq 설치)이 서버에 반영됨" || bad "jq 설치 이벤트 누락"

# 커널 하한선 + AI 리포트 (실제 PostgreSQL, 서버 컨테이너 재생성 후에도 암호화된 키가 복호화되는지까지)
adm() { curl -fsS -H "Authorization: Bearer e2e-admin" -H "Content-Type: application/json" "$@"; }
adm -X PUT $API/v1/settings/kernel-policy -d '{"rules":[{"os_family":"debian","min_kernel":"99.0"}]}' >/dev/null
nc=$(get /v1/overview | jq_ "d['noncompliant_count']")
[ "$nc" = "2" ] && pass "커널 하한선: debian 계열(ubuntu·debian) 2대만 미달, rocky 는 규칙 없어 제외" || bad "하한선 미달 수 $nc (2 기대)"
get "/v1/kernels/hosts?compliant=false" | jq_ "sorted(h['hostname'] for h in d)" | grep -q "e2e-debian.*e2e-ubuntu" && pass "미달 필터 결과가 두 debian 계열 호스트" || bad "미달 필터"

docker run -d --name swinv-e2e-llm --network $NET -v "$PWD/scripts/fake_openai.py:/f.py:ro" python:3.12-slim \
  python /f.py --host 0.0.0.0 --port 8199 --expect-key sk-e2e-secret >/dev/null
for i in $(seq 1 30); do docker logs swinv-e2e-llm 2>&1 | grep -q "fake openai on" && break; sleep 1; done
adm -X PUT $API/v1/settings/ai -d '{"base_url":"http://swinv-e2e-llm:8199/v1","model":"fake-model","trust_zone":"internal","api_key":"sk-e2e-secret"}' >/tmp/swinv-e2e-ai.json
grep -q "sk-e2e-secret" /tmp/swinv-e2e-ai.json && bad "AI 설정 응답에 키 노출" || pass "AI 설정 응답에 키가 없음"
raw=$(docker compose -p $P exec -T db psql -U swinv -d swinv -tAc "select value from app_settings where key='ai_config'")
if echo "$raw" | grep -q "enc:v1:" && ! echo "$raw" | grep -q "sk-e2e-secret"; then pass "PostgreSQL 에는 API 키가 암호문(enc:v1:)으로만 저장됨"; else bad "DB 저장 형식: $raw"; fi

docker compose -p $P up -d --force-recreate server >/dev/null 2>&1      # 컨테이너를 새로 만들어도 /data 볼륨의 키로 복호화돼야 한다
for i in $(seq 1 60); do curl -fsS $API/healthz >/dev/null 2>&1 && break; sleep 1; done
t=$(adm -X POST $API/v1/settings/ai/test | jq_ "d")
echo "$t" | grep -q "'ok': True" && pass "서버 컨테이너 재생성 후에도 저장된 키로 AI 연결 성공" || bad "재생성 후 AI 연결 실패: $t"
rep=$(adm -X POST $API/v1/reports | jq_ "d['markdown']")
echo "$rep" | grep -q "전체 3대" && echo "$rep" | grep -q "하한선 미달 2대" && pass "AI 리포트 생성: 집계(3대·미달 2대)가 LLM 에 전달돼 리포트에 반영됨" || bad "리포트 내용: $rep"
[ "$(get /v1/reports | jq_ "len(d)")" = "1" ] && pass "리포트가 PostgreSQL 에 저장됨" || bad "리포트 저장"
[ "$(get /v1/reports/facts | jq_ "d['network']['notable_exposed_ports'][0]['port']")" = "6379" ] && pass "AI 근거 집계에 노출된 redis(6379)가 포함됨" || bad "AI 집계의 네트워크"
docker logs swinv-e2e-llm 2>&1 | grep "POST /v1/chat/completions" | grep -q "key_ok=True" && pass "LLM 엔드포인트가 복호화된 API 키를 Bearer 로 받음(키는 로그에 남기지 않음)" || bad "LLM 이 올바른 키를 못 받음"

# 비특권 확인: 에이전트 실행 계정과 설정 파일 권한
docker exec swinv-e2e-rocky sh -c 'id -u swinventory; stat -c "%a %U:%G %n" /etc/swinventory/token /etc/swinventory/agent.json /var/lib/swinventory/spool.db'
docker exec swinv-e2e-rocky sh -c 'test "$(stat -c %a /etc/swinventory/token)" = 640 && test "$(stat -c %a /var/lib/swinventory/spool.db)" = 600' && pass "토큰 0640·스풀 0600 권한" || bad "파일 권한"

# 제거(uninstall) 동작
docker exec swinv-e2e-debian sh /opt/install.sh --uninstall --no-systemd >/dev/null 2>&1 && docker exec swinv-e2e-debian test ! -e /usr/local/lib/swinventory && pass "uninstall: 에이전트 제거" || bad "uninstall"

echo; [ $fail -eq 0 ] && echo "E2E 전체 통과" || echo "E2E 실패 항목 있음"
exit $fail
