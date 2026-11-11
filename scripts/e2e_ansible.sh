#!/bin/bash
# Ansible 역할 종단 검증: 서버+PostgreSQL(compose) ← ansible-core 컨테이너가 SSH 로 실제 Linux 컨테이너 2종(ubuntu·rocky)에 에이전트 배포
#   설치 → 멱등(2회차 changed=0) → --check 무변경 → 해시 불일치 거부 → 토큰 비노출(-vvv) → 제거
# 사용: scripts/e2e_ansible.sh   (docker 필요. 프로젝트명 swinv-ans 로 격리, 끝나면 모두 정리)
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PY:-.venv/bin/python}
P=swinv-ans
export WITH_WINDOWS=0
export POSTGRES_PASSWORD=ans-pg-pass SWINV_INGEST_TOKENS=ans-ingest-SECRET SWINV_READ_TOKENS=ans-read SWINV_ADMIN_TOKENS=ans-admin
export SWINV_PORT=$($PY -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
API=http://127.0.0.1:$SWINV_PORT
fail=0
pass() { echo "PASS $*"; }
bad()  { echo "FAIL $*"; fail=1; }
get()  { curl -fsS -H "Authorization: Bearer ans-read" "$API$1"; }
jq_()  { $PY -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
KEYDIR=$(mktemp -d)

cleanup() {
  docker rm -f swinv-ans-ubuntu swinv-ans-rocky swinv-ans-ctl >/dev/null 2>&1 || true
  docker compose -p $P down -v --rmi local >/dev/null 2>&1 || true
  rm -rf "$KEYDIR"
}
trap cleanup EXIT

ssh-keygen -q -t ed25519 -N '' -f "$KEYDIR/id" >/dev/null
$PY scripts/prepare_agents.py >/dev/null 2>&1 || $PY scripts/build_agent.py
docker compose -p $P up -d --build >/dev/null 2>&1
for i in $(seq 1 60); do curl -fsS $API/healthz >/dev/null 2>&1 && break; sleep 1; done
curl -fsS $API/healthz >/dev/null && pass "서버+PostgreSQL 기동" || { bad "서버 기동 실패"; exit 1; }
NET=${P}_default

target() { # name image setup-cmd
  docker run -d --name "swinv-ans-$1" --hostname "ans-$1" --network $NET "$2" sleep 3600 >/dev/null
  docker exec "swinv-ans-$1" sh -c "$3" >/dev/null 2>&1
  docker exec "swinv-ans-$1" sh -c "cat /proc/sys/kernel/random/uuid | tr -d - > /etc/machine-id; useradd -m -s /bin/bash deploy; \
    echo 'deploy ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/deploy; mkdir -p /home/deploy/.ssh /run/sshd; chmod 700 /home/deploy/.ssh"
  docker cp "$KEYDIR/id.pub" "swinv-ans-$1:/home/deploy/.ssh/authorized_keys"
  docker exec "swinv-ans-$1" sh -c "chown -R deploy:deploy /home/deploy/.ssh; chmod 600 /home/deploy/.ssh/authorized_keys; \
    ssh-keygen -A >/dev/null; /usr/sbin/sshd"
}
target ubuntu ubuntu:22.04 'apt-get update -qq && apt-get install -y -qq python3 util-linux passwd iproute2 curl sudo openssh-server'
target rocky rockylinux:9 'dnf install -y -q python3 shadow-utils util-linux iproute sudo openssh-server'

docker run -d --name swinv-ans-ctl --network $NET -v "$PWD/deploy/ansible:/ans:ro" -v "$KEYDIR/id:/key:ro" python:3.12-slim sleep 3600 >/dev/null
docker exec swinv-ans-ctl sh -c "apt-get update -qq && apt-get install -y -qq openssh-client >/dev/null && pip install -q ansible-core ansible-lint >/dev/null 2>&1 && cp /key /root/key && chmod 600 /root/key"
cat > "$KEYDIR/inv.ini" <<INV
[swinventory_targets]
swinv-ans-ubuntu
swinv-ans-rocky
[swinventory_targets:vars]
ansible_user=deploy
ansible_ssh_private_key_file=/root/key
ansible_ssh_common_args=-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
ansible_python_interpreter=/usr/bin/python3
INV
docker cp "$KEYDIR/inv.ini" swinv-ans-ctl:/root/inv.ini
printf 'swinv_ingest_token: ans-ingest-SECRET\n' > "$KEYDIR/secrets.yml"
docker cp "$KEYDIR/secrets.yml" swinv-ans-ctl:/root/secrets.yml

play() { docker exec -w /ans -e ANSIBLE_CONFIG=/ans/ansible.cfg -e ANSIBLE_HOST_KEY_CHECKING=False swinv-ans-ctl \
  ansible-playbook -i /root/inv.ini site.yml -e swinv_server_url=http://server:8000 -e swinv_allow_insecure_http=true -e @/root/secrets.yml "$@" 2>&1; }

# 0) 문법·린트
docker exec -w /ans swinv-ans-ctl ansible-playbook -i /root/inv.ini site.yml --syntax-check >/dev/null 2>&1 && pass "ansible-playbook 문법 검사" || bad "문법 검사"
if docker exec -w /ans swinv-ans-ctl ansible-lint -q site.yml roles >/tmp/swinv-ans-lint.log 2>&1; then pass "ansible-lint(production 프로파일) 통과"; else bad "ansible-lint"; sed 's/^/  /' /tmp/swinv-ans-lint.log | head -40; fi

# 1) --check: 아무것도 설치하지 않는다
play --check >/tmp/swinv-ans-check.log && pass "--check 실행 성공" || { bad "--check 실패"; tail -30 /tmp/swinv-ans-check.log; }
docker exec swinv-ans-ubuntu test -e /usr/local/lib/swinventory && bad "--check 인데 설치됨" || pass "--check 는 아무것도 설치하지 않음"
grep -qE 'changed=[1-9]' /tmp/swinv-ans-check.log && pass "--check 는 설치가 필요함을 changed 로 보고" || bad "--check 가 변경 필요를 보고하지 않음"

# 2) 설치
play >/tmp/swinv-ans-run1.log && pass "1회차 설치 성공" || { bad "1회차 실패"; tail -40 /tmp/swinv-ans-run1.log; }
[ "$(get /v1/hosts | jq_ "len(d)")" = "2" ] && pass "서버에 호스트 2대 등록(역할이 첫 수집까지 검증)" || bad "호스트 수"
docker exec swinv-ans-ubuntu sh -c 'ls /etc/swinventory/ /usr/local/lib/swinventory/ >/dev/null && stat -c %a /etc/swinventory/agent.json' | grep -qE '^(640|600)$' && pass "설정 파일 권한" || bad "설정 파일 권한"
for n in ubuntu rocky; do docker exec swinv-ans-$n sh -c 'ls /tmp | grep -c "^swinv-" || true' | grep -qx 0 && pass "[$n] 임시 디렉터리(토큰 파일) 정리됨" || bad "[$n] 임시 파일 잔존"; done

# 3) 멱등
play >/tmp/swinv-ans-run2.log && grep -E 'changed=0' /tmp/swinv-ans-run2.log | wc -l | tr -d ' ' | grep -qx 2 && pass "2회차는 changed=0 (멱등)" || { bad "멱등성"; tail -20 /tmp/swinv-ans-run2.log; }

# 4) 토큰 비노출 — 가장 상세한 -vvv 로그에도, 대상의 프로세스 목록 기록에도 없어야 한다
play -vvv --extra-vars swinv_force=true >/tmp/swinv-ans-vvv.log || true
grep -q 'ans-ingest-SECRET' /tmp/swinv-ans-vvv.log && bad "-vvv 로그에 토큰이 노출됨" || pass "-vvv 로그에 토큰이 없음"
grep -q 'ans-ingest-SECRET' /tmp/swinv-ans-run1.log /tmp/swinv-ans-run2.log && bad "일반 로그에 토큰 노출" || pass "일반 로그에 토큰이 없음"

# 5) 변조 방어: 틀린 해시 → 실패하고 기존 설치는 그대로
OLD=$(docker exec swinv-ans-ubuntu sha256sum /usr/local/lib/swinventory/swinventory-agent.pyz | cut -d' ' -f1)
if play -e swinv_agent_sha256_linux=0000000000000000000000000000000000000000000000000000000000000000 >/tmp/swinv-ans-badhash.log; then bad "해시가 틀린데 성공"; else
  grep -q "해시 불일치" /tmp/swinv-ans-badhash.log && pass "해시 불일치 → 배포 실패" || { bad "해시 불일치 메시지"; tail -20 /tmp/swinv-ans-badhash.log; }
fi
NOW=$(docker exec swinv-ans-ubuntu sha256sum /usr/local/lib/swinventory/swinventory-agent.pyz | cut -d' ' -f1)
[ "$OLD" = "$NOW" ] && pass "실패한 배포가 기존 설치를 건드리지 않음" || bad "기존 설치 변경됨"

# 6) 입력 검증
play -e swinv_server_url=ftp://x >/tmp/swinv-ans-badurl.log && bad "잘못된 URL 허용" || pass "잘못된 swinv_server_url 거부"
play -e swinv_allow_insecure_http=false >/tmp/swinv-ans-http.log && bad "평문 http 허용" || pass "평문 http 는 명시 허용 없이는 거부"

# 7) 제거
play -e swinv_state=absent -e swinv_purge=true >/tmp/swinv-ans-rm.log && pass "제거 성공" || { bad "제거 실패"; tail -30 /tmp/swinv-ans-rm.log; }
for n in ubuntu rocky; do docker exec swinv-ans-$n sh -c 'test ! -e /usr/local/lib/swinventory && test ! -e /etc/swinventory' && pass "[$n] 제거·purge 확인" || bad "[$n] 잔존"; done
play -e swinv_state=absent >/tmp/swinv-ans-rm2.log && grep -E 'changed=0' /tmp/swinv-ans-rm2.log | wc -l | tr -d ' ' | grep -qx 2 && pass "이미 제거된 서버에 다시 제거 → changed=0" || bad "제거 멱등성"

[ "$fail" = 0 ] && echo "E2E 전체 통과" || { echo "E2E 실패"; exit 1; }
