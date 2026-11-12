# swinventory

사내 서버의 **설치 소프트웨어 목록**과 **커널(OS 빌드) 버전**을 수집·관리한다.
각 서버의 에이전트가 주기적으로 수집해 중앙 서버로 올리고, 서버는 현재 상태와 변경 이력
(설치/삭제/버전 변경/커널 변경/OS 변경)을 관리하며 웹 화면과 API 로 보여준다.

```
 [Linux 에이전트(Python 3.9+, 표준 라이브러리만)] ─┐
                                                   ├─ HTTPS + Bearer ─▶ [서버: FastAPI + 웹 화면] ─▶ PostgreSQL / SQLite
 [Windows 에이전트(C#, 단일 exe)]  ───────────────┘      계약: contracts/snapshot.v1.schema.json
```

| 구성 | 상태 |
|---|---|
| Linux 에이전트 (Debian/Ubuntu, RHEL 계열) | 구현 · **실제 Ubuntu 22.04 / Debian 12 / Rocky 9 컨테이너에서 검증** |
| 서버(적재·diff·조회 API·웹 화면·보존 정리) | 구현 · **SQLite 와 PostgreSQL 16 에서 검증** |
| 배포 (Dockerfile, compose, 에이전트 `install.sh` + systemd timer) | 구현 · 컨테이너 종단 검증(`scripts/e2e_docker.sh`) |
| Windows 에이전트 (C#, `windows-agent/`) | 구현 · Linux 컨테이너에서 xUnit 88건·실제 TLS/mTLS·실제 네트워크 API·실제 서버 HTTP 업로드·트리밍 바이너리 `doctor` 검증. **레지스트리·PowerShell·예약 작업은 실제 Windows 에서 검증하지 못했다**(아래 "Windows 에이전트") |
| 커널 하한선, AI 종합 분석 리포트, 설정 화면 | 구현 · 브라우저(Chrome)와 컨테이너 종단 검증 |
| IP·MAC, 열린 포트(노출 판정·IP 충돌) | 구현 · 실제 Ubuntu/Debian/Rocky 컨테이너에서 검증 (Windows 는 Fake 만) |
| CVE/취약점, 컨테이너 이미지 | 범위 밖(모델은 확장 가능하게 설계) |

## 빠른 시작

### 화면부터 보기 (가상 데이터)

```bash
python3 -m venv .venv && . .venv/bin/activate && pip install -e '.[server,postgres,dev]'
make demo        # http://127.0.0.1:8000  로그인 토큰: demo (조회) / demo-admin (태그 수정·호스트 삭제)
```

### 서버 배포 (Docker + PostgreSQL)

```bash
cp .env.example .env       # POSTGRES_PASSWORD, SWINV_INGEST/READ/ADMIN_TOKENS 설정 (openssl rand -hex 32)
docker compose up -d --build        # 기본은 127.0.0.1:8000 에만 바인딩
```

사내망에 열 때는 `SWINV_BIND=0.0.0.0` 으로 바꾸되 **반드시 TLS 를 종단하는 리버스 프록시 뒤에** 둔다
(또는 `python -m swinventory.server serve --ssl-certfile … --ssl-keyfile …`). 토큰이 하나도 설정되지 않으면 서버는 기동을 거부한다.

### 서버 등록 — Linux·Windows 를 한 줄로

서버 화면의 **"서버 등록"**(`#/enroll`)이 대상 서버에서 실행할 설치 명령을 만들어 준다. 서버가 에이전트와 설치 스크립트를 직접 내려주므로 파일을 옮길 필요가 없다.

1. 화면에서 서버 주소를 확인한다(기본은 접속한 주소 — 대상 서버가 접근할 수 있는 주소여야 한다. 프록시 뒤라면 `SWINV_PUBLIC_URL`).
2. 필요하면 "사설 CA 사용"·"토큰 포함(관리자)"을 켜고, **복사**해서 대상 서버에서 실행한다.
3. 첫 수집이 끝나면 같은 화면의 "방금 등록된 서버"에 5초 안팎으로 나타난다.

```bash
# Linux (생성되는 명령의 모양) — 토큰은 표준입력으로 넘긴다(printf 는 셸 내장이라 ps 에 남지 않는다)
f=$(mktemp) && curl -fsSL https://inventory.example.com/install/linux.sh -o "$f" && \
  printf '%s' '<수집 토큰>' | sudo sh "$f" --token-stdin --server-url https://inventory.example.com \
  --agent-url https://inventory.example.com/download/swinventory-agent.pyz --sha256 <해시>
```
```powershell
# Windows (관리자 PowerShell) — 토큰은 환경변수로 넘긴다
$env:SWINV_TOKEN='<수집 토큰>'; $f = Join-Path $env:TEMP 'swinv-install.ps1'; Invoke-WebRequest -UseBasicParsing 'https://inventory.example.com/install/windows.ps1' -OutFile $f; powershell -NoProfile -ExecutionPolicy Bypass -File $f -ServerUrl 'https://inventory.example.com' -AgentUrl 'https://inventory.example.com/download/swinventory-agent-win-x64.exe' -Sha256 '<해시>'
```

- **무결성은 sha256 으로 고정된다.** 관리자 화면(인증된 세션)이 만든 명령에 에이전트의 해시가 박혀 있고, 설치 스크립트는 내려받은 파일의 해시가 다르면 **설치하지 않고 파일도 남기지 않는다.** 서버의 파일이 바뀌면 화면에서 명령을 다시 만든다.
- **토큰**: 기본은 자리표시자(`<수집 토큰>`)다. "토큰 포함"은 **관리자만** 쓸 수 있고 수집 전용(ingest) 토큰이 들어간다(조회·관리 권한 없음). 터미널 기록·화면 공유에 남을 수 있으니 주의한다.
- **에이전트·스크립트 다운로드는 무인증**이다(부트스트랩에 토큰이 필요하면 안 된다). 허용 목록(고정 파일명)만 내보내며 비밀이 들어 있지 않다. 인벤토리 데이터는 여전히 토큰이 필요하다.
- 대상 서버 요건 — Linux: python3 3.9+, sudo(설치만 root, 에이전트는 전용 비특권 계정), 권장 iproute2; curl·wget 이 없어도 python3 로 내려받는다. Windows: 관리자 PowerShell 5.1+(.NET 설치 불필요).
- 서버가 배포하는 파일: Docker 이미지가 `swinventory-agent.pyz`·`install.sh`·`install.ps1` 과 Windows exe 를 담는다(`SWINV_AGENT_DIR`, 기본 `/opt/swinventory/agents`). exe 빌드는 .NET SDK 스테이지에서 수 분 걸리며 `WITH_WINDOWS=0 docker compose up -d --build` 로 건너뛸 수 있다(그 경우 화면에 "서버에 없음"). 개발에서는 `make agents` 가 `dist/agents` 를 만든다.
- 수동 설치(오프라인·사전 배치): `deploy/agent/install.sh --pyz …`, `deploy/windows/install.ps1 -ExePath …`. 다운로드·해시 검증만 하려면 `--download-only`(Linux)·`-DownloadOnly`(Windows, 관리자 불필요).

설치 스크립트는 전용 비특권 계정(`swinventory`)을 만들고 토큰은 `0640 root:swinventory`, 스풀은 `0600` 으로 두며,
**root 가 아닌 그 계정으로 첫 수집을 실행해 검증**한다. 멱등이라 다시 실행하면 갱신하고, `--uninstall [--purge]` 로 제거한다.
종료 코드: 0 성공 · 1 설치/수집 실패(해시 불일치 포함) · 2 인자 오류 · 3 설치는 끝났으나 서버에 첫 전송을 못 함(스풀 보관 — 주소·토큰·방화벽·CA 확인).

### 대량 배포 — Ansible

서버가 수십~수백 대면 `deploy/ansible/` 의 역할(`swinventory_agent`)로 한 번에 배포한다. 서버 등록 한 줄 명령과 같은 안전 원칙이다 —
서버가 배포하는 에이전트를 내려받아 **sha256 을 확인**하고(기본은 컨트롤 노드가 `/download/SHA256SUMS` 조회, `swinv_agent_sha256_*` 로 직접 고정 가능),
토큰은 명령 인자가 아니라 0600 임시 파일로 넘기며 끝나면 지운다.

```bash
cd deploy/ansible
cp inventory.example.ini inventory.ini                      # 대상 서버를 swinventory_targets 에 넣는다
echo 'swinv_ingest_token: <수집 전용 토큰>' > swinv-secrets.yml && ansible-vault encrypt swinv-secrets.yml
ansible-playbook -i inventory.ini site.yml --ask-vault-pass -e swinv_server_url=https://inventory.example.com -e @swinv-secrets.yml
#   사전 점검:  … --check          제거:  … -e swinv_state=absent [-e swinv_purge=true]
```

- **멱등**: 설치된 파일의 해시가 같으면 아무것도 하지 않는다(2회차 `changed=0`). 토큰·서버 주소·CA 를 바꿨다면 `-e swinv_force=true`.
- 사설 CA: `-e swinv_ca_file=/path/ca.pem`(컨트롤 노드 경로 — 대상에 복사해 에이전트의 `ca_file` 로 설치). 평문 http 는 `swinv_allow_insecure_http=true` 일 때만(실험실 전용).
- Linux 는 SSH + sudo, Windows 는 WinRM(`ansible.windows` 컬렉션 필요: `ansible-galaxy collection install ansible.windows`).
- 검증: `make ansible-e2e` — ansible-core 컨테이너가 SSH 로 Ubuntu·Rocky 에 배포해 설치·멱등·`--check` 무변경·토큰 비노출(`-vvv`)·해시 불일치 거부·제거를 확인한다.
  **Windows 쪽(`windows.yml`)은 WinRM 대상이 없어 실행하지 못했고 `ansible-lint` 정적 검사까지만 했다.**

## Windows 에이전트 (C#)

`windows-agent/` — .NET 10, **표준 라이브러리(BCL)만 사용**(NuGet 의존성 0), self-contained 단일 `swinventory-agent.exe`(≈12MB, 트리밍). 대상 서버에 .NET 설치가 필요 없다.
Linux 에이전트(Python)와 **같은 구조·같은 의미**다: 수집기 격리, 첫 스냅샷 기준선용 `collected`/`errors`, 스풀(오래된 순 재전송), 같은 설정 키와 종료 코드. 서버와는 `contracts/` 스키마로만 만난다.

| 수집 | 방법 |
|---|---|
| 소프트웨어 | HKLM Uninstall 64/32비트(SystemComponent·ParentKeyName·업데이트 항목 제외) + `Get-HotFix`(PowerShell). `Win32_Product`(WMI)는 쓰지 않는다 |
| 커널·재부팅 | `10.0.<CurrentBuildNumber>.<UBR>`, `RebootPending`/`RebootRequired` 키 존재 여부 |
| IP·MAC·열린 포트 | **PowerShell 이 아니라 관리형 API**(`NetworkInterface`, `IPGlobalProperties`) — 관리자 권한이 필요 없고 Linux 에서도 동작해 컨테이너에서 실제로 검증했다. 루프백·링크 로컬·식별 정보 없는 터널 장치와 UDP 동적 포트(49152+)는 제외 |
| host_id | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` |

```powershell
# 빌드(맥/Linux 에서 Docker 로): windows-agent/build.sh publish  →  windows-agent/artifacts/win-x64/swinventory-agent.exe
# 서버(관리자 PowerShell):
.\deploy\windows\install.ps1 -ServerUrl https://inventory.example.com -TokenFile .\ingest-token -CaFile .\ca.pem -ExePath .\swinventory-agent.exe
swinventory-agent doctor --config "$env:ProgramData\swinventory\agent.json"      # 진단
.\deploy\windows\install.ps1 -Uninstall [-Purge]
```

- **권한**: 설치만 관리자다. 에이전트는 저권한 `NT AUTHORITY\LOCAL SERVICE` 의 **예약 작업**(기본 60분, 무작위 지연)으로 돌고, 토큰·설정은 SYSTEM/Administrators 만 쓰고 에이전트 계정은 읽기만, 스풀 폴더만 쓰기 권한을 준다(ACL).
- **`doctor`**: 레지스트리 읽기·PowerShell·네트워크 API·JSON·설정·TLS 파일·서버 연결/토큰을 항목별 PASS/FAIL/SKIP 으로 점검한다. 서버 점검은 빈 본문(`{}`)을 POST 해 **422 면 연결·TLS·토큰 정상**, 401 이면 토큰 거부, 403 이면 수집 권한 없음으로 판정하며 서버에 아무것도 저장하지 않는다. 토큰 값은 출력하지 않는다.
- 명령·옵션·종료 코드는 Python 에이전트와 같다(`collect`·`print`·`flush`·`run`·`doctor`, 0~5). `server_url` 은 https 만(개발용 `allow_insecure_http`), 사설 CA·mTLS 지원, 호스트명 검증은 사설 CA 를 써도 유지, 리다이렉트는 따르지 않는다.
- **검증 범위**: Linux 컨테이너에서 — xUnit 88건(레지스트리·PowerShell 은 Fake, 네트워크 API·프로세스 실행·HTTP·TLS/mTLS·스풀은 실제), 결함 주입 27종(`windows-agent/mutation.sh`), Python 서버가 C# 스냅샷을 받아 정확히 기대한 이벤트만 만드는지(`tests/test_csharp_contract.py`),
  실제 서버에 HTTP 업로드와 Linux 트리밍 바이너리의 `doctor`(`scripts/e2e_windows_agent.sh`), `install.ps1` 의 PowerShell 구문 검사, `win-x64` 퍼블리시와 PE 헤더 확인.
  **실제 Windows 에서 확인하지 못한 것**: `WindowsRegistryReader`(winreg 실제 호출), `Get-HotFix` 의 실제 출력과 LOCAL SERVICE 권한, `install.ps1` 의 실행(ACL·예약 작업), SChannel 에서의 PEM 클라이언트 인증서 로딩(mTLS), 트리밍된 **Windows** 바이너리의 실행. 첫 배포 때 한 대에서 `doctor` 와 `install.ps1` 을 먼저 돌려 본다.
  대상 OS 최소 버전은 .NET 10 의 지원 목록을 확인한다(오래된 Windows Server 는 `windows-agent/Directory.Build.props` 의 `TargetFramework` 한 줄로 낮출 수 있다).

## 화면

`/` (로그인: 조회 토큰, 탭을 닫으면 지워짐). 빌드 없는 정적 파일을 서버가 직접 서빙한다.

| 화면 | 내용 |
|---|---|
| 개요 | 호스트 수, 수집 정상률, 재부팅 필요, 수집 오류, 수집 끊김, **커널 하한선 미달**, **IP 충돌**, **주의 포트 노출**, 커널 분포, 최근 변경 |
| 커널 | 버전별 분포(클릭 = 필터), 호스트별 실행 중/설치된 최신 커널, 하한선·준수/미달, 재부팅 필요, 태그 필터, CSV |
| 소프트웨어 | 패키지 검색 → 버전 분포 + 설치 호스트 목록, CSV |
| 호스트 | IP 열·IP 검색, 상태(정상/수집 오류/수집 끊김) 필터, 상세(커널·**인터페이스·열린 포트**·SW 목록·변경 이력), 태그 편집, 폐기 호스트 삭제 |
| 네트워크 | IP·MAC 인벤토리(검색·충돌 표시·CSV), 열린 포트 요약(프로토콜·노출 범위·주의 포트 필터)과 포트별 호스트 목록(CSV) |
| 변경 이력 | 유형·호스트·기간 필터, CSV |
| AI 리포트 | 종합 분석 리포트 생성·조회·마크다운 저장·삭제, 근거 집계(facts) 확인 |
| 설정 | 커널 하한선 편집, AI 연결(엔드포인트·모델·키·신뢰 영역·TLS) 설정과 연결 테스트 |

호스트명·패키지명은 에이전트가 보낸 신뢰할 수 없는 값이라 화면은 `innerHTML` 없이 `textContent` 로만 그리고 CSP 헤더를 붙인다.
CSV 는 엑셀 수식 주입(`=`, `+`, `-`, `@` 로 시작하는 셀)을 막는다. 소유팀·환경은 수집이 아니라 **태그**(`team=infra`)로 서버에서 관리한다.

## 커널 하한선

설정 화면(또는 `PUT /v1/settings/kernel-policy`, admin)에서 **OS 계열별 최소 허용 커널**을 정한다.
**실행 중 커널**이 이보다 낮으면 "미달"로 표시된다 — 개요 카드, 커널 화면(필터·CSV), 호스트 목록·상세, AI 리포트에 반영된다.

| 계열 | 예시 |
|---|---|
| `debian` (Debian/Ubuntu) | `5.15.0-100` |
| `rhel` (RHEL 계열) | `5.14.0-427` |
| `windows` | `10.0.22631.3155` |
| `*` | 위 계열 규칙이 없는 모든 계열의 기본값 |

비교는 숫자 단위(`5.15.0-91 < 5.15.0-100`)이고 계열 규칙이 `*` 보다 우선한다. 저장 즉시 반영되며(새 수집을 기다리지 않음),
규칙이 없는 계열이나 커널 정보가 없는 호스트는 "판정 안 함"으로 미달에 세지 않는다. 빈 목록으로 저장하면 하한선이 해제된다.

## 자산 관리: VM/물리·시리얼·도메인·IP

웹 **자산** 탭에서 자산번호·구분(물리/VM)·시리얼·호스트명·도메인·관리 IP·상위 물리 호스트(VM 이 올라간 장비)·비고를 입력한다(쓰기는 관리자 토큰).
**자산 대장이 없어도 에이전트가 수집한 값은 모든 목록에 그대로 보인다** — 자산이 없으면 자산번호만 "미등록"이고 구분·도메인은 감지 값이다.

- **연결**: 대장과 수집 호스트는 읽을 때마다 자동 계산해 잇는다(저장하지 않아 어긋난 연결이 남지 않는다). 우선순위 **명시 지정 > 시리얼 > 호스트명 > IP**. **모호하면 연결하지 않는다**(클론된 VM 의 같은 시리얼, 같은 짧은 이름 등) — 잘못 묶는 것보다 '미수집'으로 남는 편이 안전하다. 자동 연결이 안 되는 장비는 편집 화면에서 호스트를 직접 지정한다.
- **상태**: 연결됨 / **미수집**(대장에만 있음 — 에이전트가 없는 사각지대) / **자산 미등록**(수집됐지만 대장에 없음). 대장 값과 수집 값이 다르면 구분·시리얼·IP **불일치** 배지.
- **연계**: 호스트·커널·소프트웨어 상세·변경 이력·IP·포트 상세·개요 목록에 자산번호·구분 열이 붙고(CSV 포함), 호스트 상세에는 "장비·자산" 패널, 미등록 호스트에는 수집값으로 미리 채워 주는 "자산으로 등록" 버튼이 있다.
- **수집되는 장비 정보**(수집기 `hardware`): 구분(물리/VM/컨테이너/알 수 없음)·하이퍼바이저·제조사·모델·시리얼·FQDN·도메인. Linux 는 DMI(`/sys/class/dmi/id`)·`systemd-detect-virt`(없으면 DMI 문자열·CPU 플래그·컨테이너 표식 파일), Windows 는 `Win32_ComputerSystem`·`Win32_BIOS`. **근거가 없으면 `unknown`** — 물리로 단정하지 않는다.
- **시리얼(Linux)**: 커널이 `product_serial` 을 root 만 읽게 하므로 설치 스크립트(root)가 설치 때 한 번 읽어 `/etc/swinventory/dmi_serial`(`root:swinventory 0640`)에 저장하고, 비특권 에이전트는 그 파일을 읽는다. 읽을 파일은 `--dmi-serial-file` 로 지정할 수 있다. `To Be Filled By O.E.M.`·`0000…` 같은 자리표시자 값은 시리얼로 쓰지 않는다.
- API: `GET/POST /v1/assets`(`status`=linked·uncollected·unregistered·**mismatch**), `GET/PUT/DELETE /v1/assets/{id}`, `GET /v1/assets/summary`, CSV `?format=csv`.

## 컨테이너·쿠버네티스

웹 **컨테이너** 탭: **클러스터**(노드·파드·네임스페이스·이미지, 버전 혼재 표시, 이름 지정) · **이미지**(저장소별 태그 분포 — 같은 이미지의 태그가 갈라지면 "버전 혼재") · **컨테이너**(전체 목록·필터·CSV).

컨테이너 목록·네트워크(IP·MAC)·열린 포트·소프트웨어는 **서버별 소유 목록**으로 표시하고 기본으로 접습니다. 요약의 서버 이름·ID·항목 수를 확인한 뒤 펼쳐 상세를 봅니다. 서버 필터는 이름이 아닌 `host_id`로 구분하며 검색·다른 필터와 함께 URL에 남고 CSV에도 적용됩니다. 호스트 상세의 네 범주도 기본으로 접습니다. 소프트웨어는 서버별 건수만 먼저 조회하고 펼친 서버의 패키지를 가져옵니다. 패키지·포트 상세 링크도 해당 서버 범위를 유지합니다. IP 충돌은 서버 필터와 관계없이 전체 서버 기준으로 판정합니다.

노드는 기존 호스트라서 호스트 상세의 "컨테이너" 섹션과 모든 목록의 자산번호·구분 열이 그대로 이어진다. 서버 위 도커 컨테이너도 같은 목록에 보인다.

- **쿠버네티스 API 를 쓰지 않는다**(접근 권한이 없어도 된다). 대신 **노드에 설치한 에이전트**가 노드의 컨테이너 런타임(containerd·CRI-O·docker)에서 읽는다 → **에이전트가 설치된 노드의 파드만 보이고, Deployment 같은 워크로드 단위는 알 수 없다**(파드 이름·네임스페이스는 컨테이너 라벨에서 얻는다).
- **root 권한 분리**: 런타임 소켓은 root 만 쓸 수 있고 에이전트는 root 가 아니다. `install.sh` 가 `crictl`·`docker` 가 있으면 **읽기 전용 root 헬퍼**(`containers-helper.sh`, systemd timer 15분)를 함께 설치한다. 헬퍼는 고정된 조회 명령만 실행해 **원본 출력**을 `/var/lib/swinventory-helper`(`root:swinventory 2750`, 파일 640)에 쓰고, **해석은 비특권 에이전트**가 한다. 에이전트 계정은 런타임 소켓을 직접 못 쓰고 결과 파일도 못 쓴다(e2e 가 확인). `--no-containers` 로 끄고 `--containers` 로 강제한다.
- 헬퍼는 해시로 고정된 에이전트 `.pyz` 안에 들어 있어 **별도로 내려받지 않는다**. 컨테이너 환경변수·마운트·명령줄·라벨(파드 이름·네임스페이스 제외)은 가져오지 않고, kubeconfig 에서는 `server:` 줄만 뽑는다(인증서·토큰·키는 복사하지 않음).
- **클러스터 구분은 CA 인증서 해시**(공개 정보, 모든 노드가 같음)로 한다. API 주소는 표시용이다 — k3s 는 모두 `127.0.0.1` 이라 키로 못 쓴다. CA 를 읽지 못한 노드는 "클러스터 미확인"으로 묶인다.
- **변경 이력은 이미지 단위**(`container_image_added/removed/changed`, 저장소별 태그 집합 비교). 파드 이름·컨테이너 ID 는 재시작마다 바뀌어 비교하지 않는다. 종료된 컨테이너는 실행 중인 이미지로 세지 않는다.
- 헬퍼 결과가 3시간 넘게 오래되면(타이머 정지) 마지막 값을 현재 상태로 믿지 않고 `containers` 수집 오류로 표시한다. 헬퍼가 없는 호스트는 오류가 아니라 '적용 대상 아님'이다.
- API: `GET /v1/containers`, `GET /v1/images[/{repo}?cluster=]`, `GET /v1/k8s/clusters[/{id}]`, `PUT /v1/k8s/clusters/{id}/name`(관리자). 검증: `scripts/e2e_k8s.sh`(진짜 k3s 노드) · `scripts/e2e_docker.sh`(도커).

## 네트워크: IP·MAC·열린 포트

에이전트가 서버마다 **인터페이스(이름·MAC·상태·전역 IP)** 와 **리슨 중인 포트(프로토콜·포트·바인딩 주소)** 를 수집하고, 서버는 현재 상태와 변경 이력을 관리한다.

| 수집 | 방법(Linux) | 비고 |
|---|---|---|
| 인터페이스 | `ip -j addr show`(iproute2) | 루프백·링크 로컬(fe80::, 169.254.x.x)·`veth*`(컨테이너가 만드는 쌍)·MAC도 주소도 없는 가상 장치(`gre0`, `ip6tnl0` 등)는 제외. MAC 형식이 아닌 값(터널 끝점)은 MAC 으로 받지 않는다 |
| 열린 포트 | `/proc/net/{tcp,tcp6,udp,udp6}` 직접 읽기 | `ss` 같은 도구도 root 도 필요 없다. TCP 는 LISTEN 만, UDP 는 연결 안 된 소켓 중 **시스템 임시 포트 범위(`ip_local_port_range`)를 제외**(DHCP·NTP 클라이언트 소켓이 가짜 변경을 만든다). IPv4 매핑 주소(`::ffff:a.b.c.d`)는 IPv4 로 정규화 |

- **프로세스 이름은 수집하지 않는다.** root 가 아니면 다른 사용자의 프로세스를 볼 수 없고, 보이는 것만 보이면 값이 들쭉날쭉해 가짜 변경이 생긴다(에이전트는 root 없이 동작해야 한다는 원칙).
- **노출 판정은 바인딩 주소 기준**이다: `any`(0.0.0.0·`::`), `specific`(특정 주소), `loopback`(이 호스트에서만). **방화벽 규칙은 알 수 없으므로** `any`/`specific` 은 "외부에서 접근 가능한 후보"일 뿐 실제 도달 가능성이 아니다.
- **주의 포트**(`common/ports.py`): 평문·관리·데이터 서비스(telnet, ftp, rdp, smb, snmp, redis, memcached, mongodb, mysql, postgresql, mssql, docker api 등)가 **루프백이 아닌 주소**에 바인딩된 경우. 루프백 전용(예: `127.0.0.1:5432`)은 주의 포트가 아니다.
- **IP 충돌**: 같은 IP 를 **서로 다른 호스트**가 쓰는 경우. 한 호스트의 여러 인터페이스가 같은 IP 를 갖는 것(가상 IP·본딩)은 충돌이 아니다.
- **변경 이력**: `ip_added` / `ip_removed` / `mac_changed` / `port_opened` / `port_closed`. 접두사 길이만 바뀐 것(`/24`→`/16`)이나 IP 가 인터페이스 사이를 옮겨간 것은 이벤트가 아니다. MAC 은 양쪽에 값이 있을 때만 비교한다. 루프백→전체 바인딩 같은 노출 변화는 `port_closed`+`port_opened`(detail.exposure)로 남는다.
- **기준선**: 인터페이스와 포트는 각각 처음 수집된 회차가 기준선이다. 이미 등록된 호스트의 에이전트를 올려 네트워크 데이터가 처음 도착해도 이벤트가 쏟아지지 않는다. 수집기가 실패한 회차는 이전 상태를 그대로 둔다.
- **Windows**: `Get-NetAdapter`/`Get-NetIPAddress`/`Get-NetTCPConnection -State Listen`/`Get-NetUDPEndpoint`(동적 포트 49152+ 제외)로 같은 모델에 담는다. Fake 로만 검증했다.
- **필요 조건**: 인터페이스 수집에는 iproute2(`ip`)가 필요하다(없으면 `network.interfaces` 만 실패하고 나머지는 계속 수집). 서버는 구버전 에이전트(네트워크 수집 없음)도 계속 받는다.
- AI 리포트에도 반영된다: IP 충돌, 노출된 주의 포트, 네트워크 정보를 보고하지 않는 호스트.

## AI 종합 분석 리포트

서버가 인벤토리를 집계(`GET /v1/reports/facts` — AI 설정 없이도 열람 가능)하고, 그 집계를 OpenAI 호환 API 로 보내 한국어 리포트를 받아 저장한다.
구성: 요약 · 커널 하한선 점검 · 재부팅 필요 호스트 · 수집 건전성 · 네트워크 노출·IP · 소프트웨어 버전 파편화 · 소유팀별 조치 우선순위 · 권고 조치.
**숫자와 목록은 서버가 계산**하고 AI 는 그 근거로 서술만 한다. 리포트에는 근거 집계를 함께 보관해 나중에 대조할 수 있다.

**연결 설정**(설정 화면 > AI 연결, admin) — tclient 의 사내 AI 엔드포인트 설정 규약과 같다:

| 항목 | 설명 |
|---|---|
| 엔드포인트(base_url) | OpenAI 호환 `/chat/completions` 의 기준 주소. 예) `https://llm.corp.example/v1`, 로컬 `http://127.0.0.1:11434/v1` |
| 모델 | 업스트림 모델명 |
| 신뢰 영역 | `internal`(사내 게이트웨이) / `external`(외부 서비스 — **https 필수, TLS 검증 해제 불가, 키 필수**). `api.openai.com` 은 external 로 고정 |
| API 키 | **쓰기 전용**. 암호화(Fernet, `enc:v1:`)해 저장하고 화면·API 응답에는 "저장됨"만 보인다. 비워 저장하면 기존 키 유지. 설정에 없으면 환경변수 `OPENAI_API_KEY` 폴백. 키 없는 사내 게이트웨이(로컬 Ollama 등)는 비워도 된다 |
| TLS 검증 | 기본 검증. 자가서명 사내 게이트웨이는 **사설 CA 파일(`ca_file`) 지정을 권장**하고, 검증 끄기는 internal 에서만 허용 |
| 제한 | URL 에 자격증명(`user:pw@`, `?api_key=`) 금지, 링크 로컬·클라우드 메타데이터 주소 금지, `SWINV_AI_ENDPOINT_ALLOWLIST` 로 허용 호스트 제한 가능 |

"연결 테스트"로 확인한 뒤 AI 리포트 화면에서 생성한다(admin, 동기 호출이라 수십 초~수 분, 동시에 하나만).
조회 권한 사용자는 리포트를 열람할 수 있고 생성·설정은 관리자만 가능하다.

> ⚠️ **리포트를 생성하면 호스트명·태그·커널/패키지 집계가 설정한 엔드포인트로 전송된다.** external 을 고르면 사내 인벤토리가 외부로 나가므로 신뢰 영역을 확인한다.
> 호스트명·오류 메시지 등은 에이전트가 보낸 신뢰할 수 없는 값이라, 정제·길이 제한·구분자 이스케이프·시스템 프롬프트 지침으로 프롬프트 인젝션을 막는다. AI 가 쓴 내용은 근거 집계와 대조해 확인한다.
> 암호화 키는 `SWINV_SECRET_KEY` 또는 키 파일(`SWINV_SECRET_FILE`, 없으면 자동 생성 0600)이다. **키를 잃으면 저장된 AI 키는 복호화할 수 없어 다시 입력**해야 한다(Docker 는 `/data` 볼륨에 보관).

## 에이전트

명령: `collect`(기본) · `print` · `flush` · `run --interval 3600`. 운영은 `run` 보다 **systemd timer**(install.sh 가 등록) 권장.

설정(`agent.json`, 환경변수 `SWINV_<KEY>`, CLI 옵션 순으로 덮어씀):

```json
{ "server_url": "https://inventory.example.com", "token_file": "/etc/swinventory/token",
  "ca_file": "/etc/swinventory/ca.pem", "client_cert": "…/client.pem", "client_key": "…/client.key",
  "spool_path": "/var/lib/swinventory/spool.db", "spool_max_items": 200, "timeout": 30 }
```

- `server_url` 은 https 만 허용(실험실 전용 `allow_insecure_http`). 사설 CA(`ca_file`)·mTLS 지원, 호스트명 검증은 항상 켜져 있다.
  ⚠️ Python 3.13+ 는 엄격한 인증서 검증이 기본이라 **basicConstraints/keyUsage 가 없는 대충 만든 사설 CA 는 거부**된다(3.9~3.12 는 통과). CA 를 올바른 확장으로 만든다.
- **스풀:** 전송 실패(네트워크·5xx·401/403/404/429)는 SQLite 스풀에 보관했다가 다음 실행에서 **오래된 순**으로 재전송. 400/413/422 는 `rejected` 로 격리. 상한 초과 시 가장 오래된 것부터 폐기.
- **종료 코드:** 0 성공(스풀 보관 포함) · 1 수집/전송 실패 · 2 설정 오류 · 3 미지원 플랫폼 · 4 서버 영구 거절 · 5 flush 미완료.
- **수집기 하나가 실패해도 나머지는 계속한다.** 실패는 `snapshot.errors[이름]` 에 기록된다.
- `host_id` 는 `/etc/machine-id`(비었거나 없으면 `/var/lib/dbus/machine-id`). 둘 다 없으면 `systemd-machine-id-setup` 안내와 함께 실패한다(복제된 이미지·컨테이너에서 실제로 발생).

## 수집 방법

| 플랫폼 | 소프트웨어 | 커널 / 재부팅 필요 |
|---|---|---|
| Debian/Ubuntu | `dpkg-query` (상태 `ii` 만) → `software.dpkg` | `uname -r` + `linux-image-<ver>` 패키지(메타 패키지 제외). 설치된 최신 > 실행 중이면 재부팅 필요. 패키지가 없으면(컨테이너) 실패가 아니라 실행 중 커널만 보고 |
| RHEL 계열 | `rpm -qa` (`gpg-pubkey` 제외) → `software.rpm` | `kernel-core`(RHEL8+) → 없으면 `kernel`. 동일 규칙 |
| Windows | HKLM Uninstall(64/32비트) + `Get-HotFix` → `software.win_registry`, `software.win_hotfix` | `10.0.<CurrentBuildNumber>.<UBR>`, `RebootPending`/`RebootRequired` 키 존재 여부 |

버전 비교는 숫자/문자 토큰 기반 **근사치**다(dpkg·rpm 의 완전한 규칙이 아님).

## 서버 동작 규칙 (diff)

- 호스트의 **첫 스냅샷은 기준선**이라 이벤트를 만들지 않는다.
- **수집기가 실패한 source 는 그 회차에 동기화하지 않는다**(`snapshot.collected` 에 있는 source 만) → 일시 오류로 "전부 삭제됨"이 쏟아지지 않는다.
- 호스트에서 **처음 성공한 source 도 그 source 의 기준선**이다(첫 회차에 실패했다가 나중에 성공한 경우).
- 같은 `(source, name, arch)` 의 **다중 버전 공존**(rpm `kernel-core`)은 버전 집합으로 비교한다. 양쪽 버전이 정확히 1개이고 다를 때만 `package_version_changed`, 그 외는 차집합만 `installed`/`removed`.
- 같은 `collected_at` 재전송은 `duplicate`, 현재 상태보다 오래된 스냅샷은 `stale`(보관만). 동시에 같은 스냅샷이 들어와도 유니크 충돌을 롤백 후 1회 재시도해 500 없이 수렴한다(PostgreSQL 경합 테스트로 검증).

## API

인증: `Authorization: Bearer <token>`. 역할 — `ingest`(수집 전용) / `read`(조회) / `admin`(조회 + 태그 수정·호스트 삭제). 비교는 `hmac.compare_digest`.

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/healthz` | 헬스체크(무인증, DB 확인). 실패 시 503, 내부 오류는 노출 안 함 |
| POST | `/v1/ingest` | 스냅샷 적재 → `{status, event_count}`. 본문 상한 `SWINV_MAX_BODY_BYTES`(기본 32MiB) 초과 시 413 |
| GET | `/v1/overview` | 호스트 수, 정상률, 재부팅 필요·수집 오류·수집 끊김·**하한선 미달** 수, 커널 분포, 최근 변경 |
| GET | `/v1/whoami` | 이 토큰의 역할 `{role}`(admin 또는 read)(화면이 관리자 전용 컨트롤을 미리 비활성화하는 데 쓴다. 서버 권한 검사는 그대로) |
| GET | `/v1/hosts?tag=k:v&ip=&q=&status=&format=csv` , `/v1/hosts/{id}` | 호스트 목록(`status`: ok/error/stale, `ips`, `q`=호스트명·ID·OS·자산번호·도메인·IP 부분 일치) / 상세(`interfaces`, `ports`) |
| PUT, DELETE | `/v1/hosts/{id}/tags` , `/v1/hosts/{id}` | 태그 전체 교체 / 폐기 호스트와 이력 삭제 (admin) |
| GET | `/v1/kernels` , `/v1/kernels/hosts?reboot_required=&running=&compliant=&tag=&q=&format=csv` | 커널 분포 / 호스트별 커널(`min_kernel`·`compliant` 포함) |
| GET | `/v1/software-hosts?q=&host=` | 서버별 설치 항목 수(패키지 본문 제외), 서버·패키지 이름 필터 |
| GET | `/v1/software?q=` , `/v1/software/{name}?host=&version=&below=&format=csv` | 패키지 검색 / 버전 분포 + 설치 호스트(`version`=정확히 일치, `below`=그 버전 미만 — 분포는 선택한 서버 범위 전체, version·below는 호스트 목록·CSV 만 좁힌다) |
| GET | `/v1/events?host=&type=&since=&limit=&format=csv` | 변경 이력 |
| GET | `/v1/network/ips?host=&q=&tag=&conflicts=&format=csv` , `/v1/network/ip-conflicts` | IP·MAC 인벤토리(`duplicate`=IP 충돌) / 충돌 목록 |
| GET | `/v1/network/ports?host=&proto=&exposure=` , `/v1/network/listening?host=&proto=&port=&exposure=&notable=&tag=&q=&format=csv` | 포트 요약(호스트 수·외부 바인딩 수) / 호스트×포트 평면 목록(감사·내보내기). `exposure`: any·specific·loopback·exposed(루프백 제외) |
| GET, PUT | `/v1/settings/kernel-policy` | 커널 하한선 조회(read) / 저장(admin) |
| GET, PUT, POST | `/v1/settings/ai` , `/v1/settings/ai/test` | AI 연결 설정 조회·저장·연결 테스트 (admin) |
| GET | `/v1/reports/facts` | AI 에 전달되는 집계(read) |
| POST, GET, DELETE | `/v1/reports` , `/v1/reports/{id}` | 리포트 생성(admin, 502=AI 실패 · 409=미설정 · 429=생성 중) / 목록·조회(read) / 삭제(admin) |

"정상" 은 마지막 수집에 오류가 없고 `SWINV_STALE_AFTER_HOURS`(기본 48) 안에 수집된 호스트다. `/docs` 는 OpenAPI.

## 운영

- **보존 정리**: `python -m swinventory.server prune --snapshot-days 30 --event-days 365 --host-days 180` (지정한 항목만 지운다, 기본값 없음). compose: `docker compose --profile maintenance run --rm prune` 를 cron 으로. 스냅샷 기록은 중복·역순 판정용이라 짧게, 이벤트는 길게 둔다.
- **토큰 로테이션**: `SWINV_*_TOKENS` 는 쉼표로 여러 개 — 새 토큰을 추가하고 에이전트를 교체한 뒤 옛 토큰을 뺀다.
- **폐기 서버**: 화면의 "호스트 삭제" 또는 `DELETE /v1/hosts/{id}`. 같은 `host_id` 가 다시 수집되면 새 호스트(기준선)로 등록된다.
- **입력 정제**: 수집 문자열의 제어문자(특히 PostgreSQL 이 저장하지 못하는 NUL)는 제거하고 받는다. 태그·AI 설정의 제어문자는 422, URL 의 `%00` 은 400. 네트워크 항목은 형식이 틀린 개별 항목(잘못된 IP·포트·프로토콜·MAC)만 걸러내고 나머지는 받는다 — 항목 하나가 호스트 전체 수집을 막지 않게.
- **스키마 변경**: 아직 마이그레이션 도구가 없다(`create_all`). 컬럼 추가 릴리스 전에 Alembic 도입이 필요하다.

## 에이전트↔서버 계약

`contracts/snapshot.v1.schema.json` 은 서버 수신 모델에서 **생성**한다(`PYTHONPATH=src python -m swinventory.server.contract --write`).
모델을 바꾸면 `tests/server/test_contract.py` 가 실패한다. `contracts/golden/` 예시는 서버 모델이 수용해야 한다.
**에이전트를 다른 언어로 구현해도 이 스키마만 맞추면 된다.** 서버는 미지의 필드를 무시한다.

## 테스트

```bash
make test                                   # 전체(SQLite, 약 15초)
SWINV_TEST_DB_URL=postgresql+psycopg://u:p@127.0.0.1:5432/swinv_test make test-pg   # 같은 서버 테스트를 PostgreSQL 로
scripts/e2e_docker.sh                       # 서버+PostgreSQL(compose) ← 실제 Linux 컨테이너 3종 에이전트 종단 검증(하한선·AI 리포트·컨테이너 재생성 후 키 복호화 포함)
```

`SWINV_TEST_DB_URL` 의 DB 는 매 테스트마다 **모든 테이블을 DROP** 하므로 이름에 `test` 가 없으면 거부한다.
e2e 는 실제로 패키지를 설치/제거한 뒤 재수집해 이벤트를 확인하고, 서버를 내렸다 올려 스풀·재전송까지 검증한다. 가짜 OpenAI 서버(`scripts/fake_openai.py`)로 AI 리포트를 생성하고, 서버 컨테이너를 재생성한 뒤에도 암호화된 키가 복호화되는지 확인한다.

## 디렉터리

```
src/swinventory/
  common/    모델·버전 비교(agent·server 공유, 표준 라이브러리만)
  agent/     runtime/(명령·파일·레지스트리 추상화) collectors/ profiles/ transport/ orchestrator cli config
  server/    repo/(Repository ABC + SQLAlchemy Core) services/ingest diff policy secrets ai/(llm·config·facts·prompt·service) api/ web/(화면) auth middleware cli main app contract
contracts/   JSON Schema + golden 예시          deploy/agent/   install.sh (+ systemd unit 생성)
scripts/     build_agent.py seed_demo.py fake_openai.py e2e_docker.sh      Dockerfile · docker-compose.yml · Makefile
tests/       agent/ common/ server/ test_e2e.py(에이전트→서버 층간 계약)
```

## 한계

- 컨테이너 수집은 **containerd(k3s)·docker 만 실제 출력으로 검증**했다. CRI-O·rke2·kubeadm 의 `crictl`/`kubelet.conf` 경로와 podman 은 코드에 경로·형식 처리만 있고 실제 클러스터에서 확인하지 못했다. Windows 컨테이너는 수집하지 않는다.
- 쿠버네티스 노드의 파드는 에이전트가 설치된 노드만 보인다(API 미사용). 설치되지 않은 노드의 파드·워크로드는 알 수 없다.
- 장비 정보 수집은 Windows(`Win32_BIOS` 시리얼을 LOCAL SERVICE 로 조회, CIM 조회)를 실제 Windows 에서 검증하지 못했다. Linux 는 Docker 컨테이너에서 검증했고 **물리 서버·실제 VM 의 DMI 값(`product_name` 등)은 실제 장비에서 확인하지 못했다**(판정 규칙은 공유 벡터·단위 테스트로만 검증). 첫 배포 때 대표 장비 몇 대에서 '구분'이 맞는지 확인한다.
- 자산 연결·집계는 서버가 요청마다 파이썬으로 계산한다(수천 대 규모 가정, 호스트 목록 계열 조회마다 대장·호스트·장비 정보를 한 번씩 읽는다).
- Ansible 역할의 Windows 부분(WinRM, `win_*` 모듈)은 실제 Windows 에서 실행하지 못했다. Linux 부분은 e2e 로 검증했다.
- 서버 등록 명령의 토큰은 수집 전용 공용 토큰이다(호스트별 토큰·일회용 등록 토큰은 아직 없다). 토큰을 바꾸려면 `SWINV_INGEST_TOKENS` 에 새 토큰을 추가하고 에이전트를 다시 설치한 뒤 옛 토큰을 뺀다.
- Windows 의 한 줄 설치(`install.ps1` 의 실제 실행·예약 작업·ACL)와 사설 CA 로 서버가 서빙될 때의 Windows 다운로드는 실제 Windows 에서 검증하지 못했다(다운로드·해시 검증 로직만 PowerShell 7 에서 검증).

- 에이전트의 **systemd 유닛 파일은 시스템에서 실제로 구동해 보지 못했다**(컨테이너에는 systemd 가 없어 `--no-systemd` 경로로 검증). 첫 배포 때 `systemctl status swinventory.timer` 로 확인한다.
- Windows 에이전트(C#)는 레지스트리·PowerShell·예약 작업·ACL 을 실제 Windows 에서 돌려 보지 못했다(위 "Windows 에이전트"의 검증 범위 참고). 첫 배포 때 한 대에서 `doctor` 로 먼저 확인한다.
- RHEL 7/8 의 기본 Python(3.6)은 지원하지 않는다(3.9+ 필요 — RHEL 9 기본 3.9 는 검증됨).
- AI 리포트의 "동시에 하나만 생성" 잠금은 프로세스 단위다(uvicorn 워커가 여러 개면 워커마다 하나). 리포트 생성은 동기 호출이라 프록시 타임아웃을 120초 이상으로 둔다.
- 하한선 판정과 네트워크 집계(IP 충돌·포트 요약·노출 판정)는 서버가 요청마다 파이썬에서 계산한다(수천 대 규모 가정). 수만 대로 늘면 캐시 또는 수집 시점 계산이 필요하다.
- 노출 판정은 바인딩 주소 기준이라 방화벽·보안그룹·NAT 은 반영되지 않는다. 프로세스(어떤 서비스가 여는지)는 root 가 필요해 수집하지 않는다.
- AI 리포트 품질(문장·판단)은 모델에 달렸고 이 저장소의 테스트는 실제 LLM 이 아니라 호환 서버로 요청·응답 처리와 안전성만 검증했다.
- HA 구성(서버 다중화), 스키마 마이그레이션(Alembic), 감사 로그는 아직 없다.
