#!/bin/bash
# 쿠버네티스 노드 종단 검증: 서버+PostgreSQL(compose) ← 진짜 k3s 가 도는 Debian 노드(특권 컨테이너)에서 install.sh 로 에이전트+root 헬퍼를 설치
#   crictl(실제 containerd) → root 헬퍼 → 비특권 에이전트 → 서버: 클러스터 식별(CA 해시)·파드·이미지·권한 분리를 확인한다.
# k3s 는 공식 rancher/k3s 이미지(버전 고정)에서 바이너리만 꺼내 Debian 노드에 넣는다 — 원격 설치 스크립트를 내려받아 실행하지 않는다.
# 사용: scripts/e2e_k8s.sh   (docker·인터넷 필요 — 이미지·파드 이미지를 내려받는다. 프로젝트명 swinv-k8s 로 격리하고 끝나면 정리한다)
set -euo pipefail
cd "$(dirname "$0")/.."
PY=${PY:-.venv/bin/python}
P=swinv-k8s
K3S_IMAGE=${K3S_IMAGE:-rancher/k3s:v1.34.1-k3s1}
export WITH_WINDOWS=0 POSTGRES_PASSWORD=k8s-pg-pass SWINV_INGEST_TOKENS=k8s-ingest SWINV_READ_TOKENS=k8s-read SWINV_ADMIN_TOKENS=k8s-admin
export SWINV_PORT=$($PY -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
API=http://127.0.0.1:$SWINV_PORT
fail=0
pass() { echo "PASS $*"; }
bad()  { echo "FAIL $*"; fail=1; }
get()  { curl -fsS -H "Authorization: Bearer k8s-read" "$API$1"; }
jq_()  { $PY -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
node() { docker exec swinv-k8s-node "$@"; }
cleanup() { docker rm -fv swinv-k8s-node swinv-k8s-k3simg >/dev/null 2>&1 || true; rm -rf /tmp/swinv-k3s-bin; docker compose -p $P down -v --rmi local >/dev/null 2>&1 || true; }
trap cleanup EXIT

$PY scripts/build_agent.py >/dev/null
docker rm -f swinv-k8s-k3simg >/dev/null 2>&1 || true
docker create --name swinv-k8s-k3simg "$K3S_IMAGE" >/dev/null && rm -rf /tmp/swinv-k3s-bin && docker cp swinv-k8s-k3simg:/bin /tmp/swinv-k3s-bin && docker rm swinv-k8s-k3simg >/dev/null
docker compose -p $P up -d --build >/dev/null 2>&1
for i in $(seq 1 60); do curl -fsS $API/healthz >/dev/null 2>&1 && break; sleep 1; done
curl -fsS $API/healthz >/dev/null && pass "서버+PostgreSQL 기동" || { bad "서버 기동 실패"; exit 1; }
NET=${P}_default

# 컨테이너 루트가 overlay 라 그 위에서 containerd 의 overlayfs 를 쓸 수 없다 — 공식 이미지가 VOLUME 으로 선언한 경로들을 익명 볼륨으로 마운트한다(정리할 때 -v 로 함께 지운다)
docker run -d --privileged --name swinv-k8s-node --hostname k8s-node1 --network $NET --tmpfs /run --tmpfs /var/run \
  -v /var/lib/rancher/k3s -v /var/lib/kubelet -v /var/lib/cni -v /var/log \
  -v "$PWD/dist/swinventory-agent.pyz:/opt/a.pyz:ro" -v "$PWD/deploy/agent/install.sh:/opt/install.sh:ro" debian:12 sleep infinity >/dev/null
node sh -c 'apt-get update -qq && apt-get install -y -qq python3 util-linux passwd curl ca-certificates iproute2 sudo >/dev/null 2>&1 && cat /proc/sys/kernel/random/uuid | tr -d - > /etc/machine-id'
# 이미지의 /bin 은 libc 없는 정적 실행 파일 모음(k3s·containerd·runc·CNI 플러그인, aux/ 에 iptables 계열)이라 Debian 노드에 그대로 복사해 쓸 수 있다
docker cp /tmp/swinv-k3s-bin swinv-k8s-node:/opt/k3s
node sh -c 'ln -sf /opt/k3s/k3s /usr/local/bin/k3s && ln -sf /opt/k3s/k3s /usr/local/bin/crictl && ln -sf /opt/k3s/k3s /usr/local/bin/kubectl'
node k3s --version | head -1 | sed 's/^/  /'
echo "  k3s 기동 중(파드 이미지를 내려받느라 몇 분 걸릴 수 있다)…"
# cgroup v2 중첩: 루트 cgroup 에 프로세스가 있으면 kubelet 이 kubepods 를 만들지 못한다 — 공식 이미지 진입점처럼 init 하위 그룹으로 옮기고 컨트롤러를 켠다
node sh -c 'if [ -f /sys/fs/cgroup/cgroup.controllers ]; then mkdir -p /sys/fs/cgroup/init; xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || :; sed -e "s/ / +/g" -e "s/^/+/" < /sys/fs/cgroup/cgroup.controllers > /sys/fs/cgroup/cgroup.subtree_control; fi'
node sh -c 'PATH=$PATH:/opt/k3s:/opt/k3s/aux nohup k3s server --disable traefik --disable metrics-server --disable servicelb "--kubelet-arg=eviction-hard=imagefs.available<1%,nodefs.available<1%" "--kubelet-arg=eviction-minimum-reclaim=imagefs.available=1%,nodefs.available=1%" >/tmp/k3s.log 2>&1 &'
for i in $(seq 1 90); do node kubectl get nodes 2>/dev/null | grep -q " Ready" && break; sleep 3; done
node kubectl get nodes 2>/dev/null | grep -q " Ready" && pass "k3s 노드 Ready" || { bad "k3s 가 준비되지 않았다"; node tail -5 /tmp/k3s.log; exit 1; }
for i in $(seq 1 60); do [ "$(node kubectl get pods -A --no-headers 2>/dev/null | grep -c ' Running')" -ge 2 ] && break; sleep 3; done
node kubectl get pods -A --no-headers 2>&1 | sed 's/^/  /'

# --- 에이전트 + root 헬퍼 설치(crictl 이 PATH 에 있으니 헬퍼가 자동 설치된다) ---
node sh /opt/install.sh --server-url http://server:8000 --allow-insecure-http --token k8s-ingest --pyz /opt/a.pyz --no-systemd >/tmp/k8s-install.log 2>&1 \
  && pass "install.sh 로 에이전트+컨테이너 헬퍼 설치·첫 수집" || { bad "설치 실패"; tail -15 /tmp/k8s-install.log; }
grep -q "컨테이너 헬퍼 설치" /tmp/k8s-install.log && pass "crictl 을 보고 헬퍼를 자동 설치" || bad "헬퍼 자동 설치 안 됨"

hid=$(get /v1/hosts | jq_ "[h for h in d if h['hostname']=='k8s-node1'][0]['host_id']")
CA=$(node sha256sum /var/lib/rancher/k3s/agent/server-ca.crt | cut -d' ' -f1)
d=$(get /v1/hosts/$hid)
[ "$(echo "$d" | jq_ "d['k8s']['cluster_id']")" = "$CA" ] && pass "클러스터 식별: 서버가 아는 cluster_id 가 노드의 CA 인증서 해시와 같다(API 주소가 127.0.0.1 이어도)" || bad "cluster_id: $(echo "$d" | jq_ "d['k8s']")"
echo "$d" | jq_ "d['k8s']['version']" | grep -qE '^v1\.[0-9]+\.[0-9]+' && pass "쿠버네티스 버전 수집: $(echo "$d" | jq_ "d['k8s']['version']")" || bad "버전"
echo "$d" | jq_ "(d['k8s']['api_server'], d['k8s']['runtime'])" | grep -q "127.0.0.1:6443.*containerd" && pass "API 주소는 표시용(루프백)·런타임 containerd" || bad "api/runtime: $(echo "$d" | jq_ "d['k8s']")"
names=$(echo "$d" | jq_ "sorted((c['namespace'], c['name']) for c in d['containers'] if c['state']=='running')")
echo "$names" | grep -q "('kube-system', 'coredns')" && echo "$names" | grep -q "('kube-system', 'local-path-provisioner')" && pass "실제 파드 컨테이너 수집(coredns, local-path-provisioner)" || bad "컨테이너: $names"
echo "$d" | jq_ "all(not c['image'].startswith('sha256:') and c['pod'] for c in d['containers'] if c['state']=='running')" | grep -q True && pass "이미지는 읽을 수 있는 이름, 파드 이름이 함께 수집됨" || bad "이미지/파드: $(echo "$d" | jq_ "[(c['image'], c['pod']) for c in d['containers']]")"
cl=$(get /v1/k8s/clusters)
[ "$(echo "$cl" | jq_ "(len(d), d[0]['node_count'], d[0]['pod_count'] >= 2)")" = "(1, 1, True)" ] && pass "클러스터 1개·노드 1개·파드 2개 이상으로 집계" || bad "클러스터 집계: $cl"

# --- 권한 분리: 비특권 에이전트는 런타임을 직접 못 쓰고 헬퍼 결과를 위조할 수 없다 ---
if node runuser -u swinventory -- crictl ps >/dev/null 2>&1; then bad "에이전트 계정이 containerd 를 직접 쓸 수 있다"; else pass "에이전트 계정은 containerd 를 직접 쓸 수 없다(root 헬퍼만 읽음)"; fi
if node runuser -u swinventory -- sh -c 'touch /var/lib/swinventory-helper/forged' >/dev/null 2>&1; then bad "에이전트 계정이 헬퍼 결과를 쓸 수 있다"; else pass "에이전트 계정은 헬퍼 결과를 위조할 수 없다"; fi
if node grep -rqE 'PRIVATE KEY|client-key-data|token:' /var/lib/swinventory-helper; then bad "헬퍼 결과에 kubeconfig 의 비밀이 들어 있다"; else pass "헬퍼 결과에 kubeconfig 의 키·토큰이 없다(server: 줄과 CA 해시만)"; fi

# --- 변경: 새 이미지를 쓰는 파드를 띄우면 이미지 추가 이벤트가 생긴다 ---
node kubectl run swinv-probe --image=rancher/mirrored-library-busybox:1.36.1 --restart=Never -- sleep 600 >/dev/null 2>&1 || true
for i in $(seq 1 40); do node crictl ps -o json 2>/dev/null | grep -q '"swinv-probe"' && break; sleep 3; done
node sh /usr/local/lib/swinventory/containers-helper.sh /var/lib/swinventory-helper
node runuser -u swinventory -- python3 /usr/local/lib/swinventory/swinventory-agent.pyz collect --config /etc/swinventory/agent.json >/dev/null 2>&1 && pass "재수집" || bad "재수집 실패"
ev=$(get "/v1/events?type=container_image_added" | jq_ "[(e['subject_key'], e['new_value']) for e in d]")
echo "$ev" | grep -q "mirrored-library-busybox" && pass "새 이미지를 쓰는 파드 → container_image_added: $ev" || { bad "이벤트: $ev (파드 상태: $(node kubectl get pod swinv-probe --no-headers 2>&1))"; node kubectl describe pod swinv-probe 2>&1 | sed -n '/Events:/,$p' | sed 's/^/  /'; node kubectl describe node 2>&1 | grep -iE "taint|pressure" | sed 's/^/  /'; }

[ "$fail" = 0 ] && echo "E2E 전체 통과" || { echo "E2E 실패"; exit 1; }
