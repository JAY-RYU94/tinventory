#!/bin/sh
# swinventory 컨테이너 헬퍼 — root 로 실행되는 **읽기 전용** 조회 스크립트(systemd timer).
#
# 컨테이너 런타임 소켓(containerd·docker)은 root 만 쓸 수 있고, 에이전트는 root 없이 돈다. 그래서 이 스크립트가 고정된 조회 명령만
# 실행해 원본 출력을 $OUT 에 쓰고, **해석은 비특권 에이전트가 한다**(root 로 도는 코드를 이 수십 줄로 한정한다).
#   - 실행하는 명령: crictl ps|images|version, docker ps|images, kubelet|k3s|rke2 --version, sha256sum(CA 인증서), grep(server: 줄)
#   - 쓰는 곳: $OUT 한 곳(root:swinventory 0750, 파일 0640). 다른 곳은 건드리지 않는다.
#   - 복사하지 않는 것: kubeconfig 의 인증서·토큰·키(server: 줄만 뽑는다), 컨테이너 환경변수·마운트·명령줄.
set -u
OUT=${1:-/var/lib/swinventory-helper}
T=${SWINV_HELPER_TIMEOUT:-30}
umask 027
mkdir -p "$OUT" || exit 1
TMP=$(mktemp -d "$OUT/.tmp.XXXXXX") || exit 1
trap 'rm -rf "$TMP"' EXIT

have() { command -v "$1" >/dev/null 2>&1; }
run()  { # name cmd...  — 시간 제한. 실패하면 해당 파일을 만들지 않는다(에이전트가 '없음'과 '실패'를 구분한다)
  name=$1; shift
  if have timeout; then timeout "$T" "$@" >"$TMP/$name" 2>"$TMP/$name.err" || rm -f "$TMP/$name"
  else "$@" >"$TMP/$name" 2>"$TMP/$name.err" || rm -f "$TMP/$name"; fi
  rm -f "$TMP/$name.err"
}

# --- CRI(containerd·CRI-O·cri-dockerd): crictl ---
if have crictl; then
  EP=""
  for sock in /run/containerd/containerd.sock /run/k3s/containerd/containerd.sock /var/run/crio/crio.sock /run/crio/crio.sock /run/cri-dockerd.sock; do
    [ -S "$sock" ] && { EP="unix://$sock"; break; }
  done
  if [ -n "$EP" ]; then
    run crictl_ps.json     crictl --runtime-endpoint "$EP" --image-endpoint "$EP" ps -a -o json
    run crictl_images.json crictl --runtime-endpoint "$EP" --image-endpoint "$EP" images -o json
    run crictl_version.txt crictl --runtime-endpoint "$EP" --image-endpoint "$EP" version
  fi
fi

# --- Docker: 필요한 필드만(라벨·환경변수·마운트·명령줄은 가져오지 않는다) ---
if have docker && [ -S /var/run/docker.sock ]; then
  run docker_ps.jsonl     docker ps -a --no-trunc --format '{"id":{{json .ID}},"name":{{json .Names}},"image":{{json .Image}},"state":{{json .State}},"created":{{json .CreatedAt}}}'
  run docker_images.jsonl docker images --digests --no-trunc --format '{"repository":{{json .Repository}},"tag":{{json .Tag}},"digest":{{json .Digest}},"id":{{json .ID}}}'
fi

# --- 쿠버네티스 노드 식별: 클러스터 CA 인증서 해시(공개 정보·모든 노드가 같음) + API 서버 주소(표시용) + 버전 ---
# 주소는 k3s 처럼 루프백(127.0.0.1)일 수 있어 클러스터를 구분하는 키로 쓰지 못한다 — 구분은 CA 해시로 한다.
for ca in /etc/kubernetes/pki/ca.crt /var/lib/rancher/rke2/agent/server-ca.crt /var/lib/rancher/k3s/agent/server-ca.crt; do
  if [ -r "$ca" ]; then sha256sum "$ca" | cut -d' ' -f1 > "$TMP/k8s_ca_sha256.txt"; break; fi
done
for kc in /etc/kubernetes/kubelet.conf /var/lib/rancher/rke2/agent/kubelet.kubeconfig /var/lib/rancher/k3s/agent/kubelet.kubeconfig; do
  if [ -r "$kc" ]; then grep -m1 '^ *server:' "$kc" | sed 's/^ *server: *//' > "$TMP/k8s_server.txt"; break; fi
done
if   have kubelet; then run k8s_version.txt kubelet --version
elif have rke2;    then run k8s_version.txt rke2 --version
elif have k3s;     then run k8s_version.txt k3s --version; fi

# 수집 시각(에이전트가 오래된 결과를 현재 상태로 믿지 않게 한다)
date +%s > "$TMP/collected_at.txt"

# 원자적 교체: 파일 단위로 mv. 이번에 만들어지지 않은 파일(런타임이 사라짐 등)은 이전 값을 남기지 않는다.
for f in "$OUT"/*; do
  [ -f "$f" ] || continue
  [ -e "$TMP/$(basename "$f")" ] || rm -f "$f"
done
for f in "$TMP"/*; do
  [ -f "$f" ] || continue
  chmod 0640 "$f"; mv -f "$f" "$OUT/$(basename "$f")"
done
