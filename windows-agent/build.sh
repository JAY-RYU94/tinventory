#!/bin/bash
# Windows 에이전트(C#) 빌드·테스트·퍼블리시를 Docker 의 .NET SDK 컨테이너에서 수행한다(호스트에 SDK 설치 불필요).
#   windows-agent/build.sh test                 # xUnit (Linux 컨테이너 — 레지스트리·PowerShell 은 Fake, 네트워크 API·TLS 는 실제)
#   windows-agent/build.sh publish              # artifacts/win-x64/swinventory-agent.exe (self-contained 단일 파일)
#   windows-agent/build.sh contract             # C# 가 만든 스냅샷을 artifacts/*.json 으로 내보낸다(Python 서버 계약 테스트 tests/test_csharp_contract.py 용)
#   windows-agent/build.sh publish-linux        # 같은 코드의 Linux 트리밍 바이너리(doctor 로 실제 실행 검증용): artifacts/linux/
#   SWINV_E2E_SERVER=http://host.docker.internal:8130 SWINV_E2E_TOKEN=… windows-agent/build.sh interop   # 실제 서버에 HTTP 로 업로드
set -euo pipefail
cd "$(dirname "$0")"
IMAGE=${DOTNET_IMAGE:-mcr.microsoft.com/dotnet/sdk:10.0}
run() { docker run --rm -v "$PWD/..:/repo" -v swinv-nuget:/root/.nuget/packages -w /repo/windows-agent \
  -e DOTNET_CLI_TELEMETRY_OPTOUT=1 -e DOTNET_NOLOGO=1 "$@"; }
case "${1:-test}" in
  test)     run "$IMAGE" dotnet test tests/Swinventory.Agent.Tests --nologo -v q "${@:2}" ;;
  publish)  run "$IMAGE" dotnet publish src/Swinventory.Agent -c Release -r win-x64 --self-contained \
              -p:PublishSingleFile=true -p:PublishTrimmed=true -p:EnableCompressionInSingleFile=true -o artifacts/win-x64 ;;
  contract) run -e SWINV_CONTRACT_OUT=/repo/windows-agent/artifacts "$IMAGE" \
              dotnet test tests/Swinventory.Agent.Tests --nologo -v q --filter "FullyQualifiedName~ContractEmit" ;;
  interop)  run --add-host host.docker.internal:host-gateway -e SWINV_E2E_SERVER -e SWINV_E2E_TOKEN "$IMAGE" \
              dotnet test tests/Swinventory.Agent.Tests --nologo -v q --filter "FullyQualifiedName~ServerInterop" ;;
  publish-linux) RID=$([ "$(uname -m)" = "x86_64" ] && echo linux-x64 || echo linux-arm64)
            run "$IMAGE" dotnet publish src/Swinventory.Agent -c Release -r "$RID" --self-contained \
              -p:PublishSingleFile=true -p:PublishTrimmed=true -p:EnableCompressionInSingleFile=true -o artifacts/linux ;;
  *) echo "usage: $0 test|publish|publish-linux|contract|interop" >&2; exit 2 ;;
esac
