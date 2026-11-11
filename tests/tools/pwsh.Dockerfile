# Linux 에서 install.ps1 의 다운로드·해시 검증(-DownloadOnly)을 실제로 실행하기 위한 PowerShell 이미지.
# MCR 의 PowerShell 이미지는 amd64 위주라 Apple Silicon 에서는 에뮬레이션으로 불안정하다 → 네이티브 .NET SDK 위에 전역 도구로 설치한다.
#   docker build -t swinv-pwsh -f tests/tools/pwsh.Dockerfile tests/tools      (make pwsh-image)
FROM mcr.microsoft.com/dotnet/sdk:10.0
ENV DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_ROLL_FORWARD=LatestMajor PATH="${PATH}:/root/.dotnet/tools"
RUN dotnet tool install --global PowerShell
