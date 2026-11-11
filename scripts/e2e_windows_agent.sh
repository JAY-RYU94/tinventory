#!/bin/bash
# C# Windows 에이전트 종단 검증(Linux 컨테이너에서 가능한 범위):
#   1) 실제 Python 서버(uvicorn)에 C# 클라이언트(HttpClient)가 HTTP 로 스냅샷 2건을 올린다 → 서버 diff 가 기대한 이벤트만 만든다
#   2) 같은 코드의 Linux 트리밍 바이너리로 `doctor` 를 실제 실행 — 정상 토큰·잘못된 토큰(401)·조회 토큰(403)·서버 없음
# Windows 에서만 실행되는 부분(레지스트리·PowerShell·서비스 계정 권한)은 여기서 검증할 수 없다.
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PY:-.venv/bin/python}
PORT=$($PY -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
DB=$(mktemp -t swinv-winagent).db
API=http://127.0.0.1:$PORT
fail=0
pass() { echo "PASS $*"; }
bad()  { echo "FAIL $*"; fail=1; }
get()  { curl -fsS -H "Authorization: Bearer rd" "$API$1"; }
jq_()  { $PY -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
cleanup() { [ -n "${SRV:-}" ] && kill "$SRV" 2>/dev/null || true; rm -f "$DB"; }
trap cleanup EXIT

SWINV_DB_URL=sqlite:///$DB SWINV_INGEST_TOKENS=ing SWINV_READ_TOKENS=rd SWINV_ADMIN_TOKENS=adm SWINV_SECRET_FILE=$DB.key \
  $PY -m swinventory.server serve --host 0.0.0.0 --port $PORT --log-level warning >/tmp/swinv-winagent-srv.log 2>&1 &
SRV=$!
for i in $(seq 1 40); do curl -fsS $API/healthz >/dev/null 2>&1 && break; sleep 0.5; done
curl -fsS $API/healthz >/dev/null && pass "서버 기동" || { bad "서버 기동 실패"; cat /tmp/swinv-winagent-srv.log; exit 1; }

# 1) C# HttpClient → 실제 서버
if SWINV_E2E_SERVER=http://host.docker.internal:$PORT SWINV_E2E_TOKEN=ing windows-agent/build.sh interop >/tmp/swinv-winagent-interop.log 2>&1; then
  pass "C# HttpClient 가 실제 서버에 스냅샷 2건을 HTTP 로 업로드"
else bad "C# 업로드 실패"; tail -20 /tmp/swinv-winagent-interop.log; fi
HOST=11111111-2222-3333-4444-555555555555
d=$(get /v1/hosts/$HOST) || { bad "호스트가 등록되지 않음"; exit 1; }
echo "$d" | jq_ "d['host']['os_family']+'|'+d['host']['os_name']+'|'+d['kernel']['running']" | grep -q "windows|Windows Server 2022 Standard|10.0.20348.2500" && pass "Windows 호스트로 등록(OS·커널은 두 번째 스냅샷 값)" || bad "호스트 정보"
ev=$(get "/v1/events?host=$HOST" | jq_ "sorted((e['event_type'], e['subject_key']) for e in d)")
want="[('ip_added', '10.1.2.4'), ('ip_removed', '10.1.2.3'), ('kernel_changed', 'running'), ('package_installed', 'KB5036000'), ('package_version_changed', 'Git'), ('port_opened', 'tcp/8443')]"
[ "$ev" = "$want" ] && pass "변경 이벤트가 정확히 6건: 설치·버전 변경·포트 열림·IP 교체·커널 업데이트" || bad "이벤트 불일치: $ev"
notable=$(get "/v1/network/listening?notable=true" | jq_ "sorted({(r['port'], r['service']) for r in d})")
[ "$notable" = "[(135, 'msrpc'), (3389, 'rdp')]" ] && pass "전체 바인딩된 MSRPC(135)·RDP(3389)가 주의 포트로 식별되고, 루프백 전용 5432 는 제외됨" || bad "주의 포트: $notable"

# 2) Linux 트리밍 바이너리로 doctor 실행
if windows-agent/build.sh publish-linux >/tmp/swinv-winagent-pub.log 2>&1; then pass "Linux 트리밍 단일 파일 바이너리 퍼블리시"; else bad "Linux 퍼블리시 실패"; tail /tmp/swinv-winagent-pub.log; exit 1; fi
agent() { # env... -- args...
  docker run --rm --add-host host.docker.internal:host-gateway -v "$PWD/windows-agent/artifacts/linux:/a:ro" \
    -e SWINV_ALLOW_INSECURE_HTTP=true "$@"
}
IMG=mcr.microsoft.com/dotnet/runtime-deps:10.0
run_doctor() { agent -e SWINV_TOKEN="$1" $IMG /a/swinventory-agent doctor --server-url "$2" 2>&1; }
out=$(run_doctor ing http://host.docker.internal:$PORT) && rc=0 || rc=$?
echo "$out" | sed 's/^/  | /'
[ $rc -eq 0 ] && grep -q "^PASS 서버 연결·토큰" <<<"$out" && pass "doctor(정상 토큰): 트리밍된 실제 바이너리가 서버에 연결·토큰 검증을 통과(exit 0)" || bad "doctor 정상 (rc=$rc)"
grep -q "^PASS JSON 직렬화" <<<"$out" && grep -q "^PASS 네트워크 API" <<<"$out" && pass "doctor: 트리밍 빌드에서 JSON(source generator)·네트워크 API 가 동작" || bad "doctor JSON/네트워크"
grep -q "^SKIP 레지스트리 읽기" <<<"$out" && pass "doctor: Windows 가 아니면 레지스트리 점검은 SKIP" || bad "doctor SKIP"
out=$(run_doctor wrong http://host.docker.internal:$PORT) && rc=0 || rc=$?
[ $rc -eq 1 ] && grep -q "FAIL 서버 연결·토큰.*401" <<<"$out" && ! grep -q "wrong" <<<"$out" && pass "doctor(잘못된 토큰): 401 로 FAIL, 토큰 값은 출력하지 않음(exit 1)" || bad "doctor 401 (rc=$rc)"
out=$(run_doctor rd http://host.docker.internal:$PORT) && rc=0 || rc=$?
[ $rc -eq 1 ] && grep -q "FAIL 서버 연결·토큰.*403" <<<"$out" && pass "doctor(조회 토큰): 수집 권한 없음 403 으로 FAIL" || bad "doctor 403 (rc=$rc)"
out=$(run_doctor ing http://host.docker.internal:1) && rc=0 || rc=$?
[ $rc -eq 1 ] && grep -q "FAIL 서버 연결·토큰.*연결하지 못했다" <<<"$out" && pass "doctor(서버 없음): 연결 실패로 FAIL" || bad "doctor 연결 실패 (rc=$rc)"
agent $IMG /a/swinventory-agent print >/dev/null 2>/tmp/swinv-winagent-print.err && rc=0 || rc=$?
[ $rc -eq 3 ] && grep -q "Windows" /tmp/swinv-winagent-print.err && pass "Linux 에서 collect/print 는 종료 코드 3(Windows 전용 안내)" || bad "비 Windows 종료 코드 (rc=$rc)"
agent $IMG /a/swinventory-agent --help >/dev/null && pass "--help 정상" || bad "--help"

echo; [ $fail -eq 0 ] && echo "E2E 전체 통과" || echo "E2E 실패 항목 있음"
exit $fail
