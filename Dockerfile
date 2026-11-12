# swinventory 서버(API + 화면 + 에이전트 배포).
# 에이전트(Linux .pyz, Windows exe)와 설치 스크립트를 이미지에 담아 서버가 직접 내려준다 → 화면의 "서버 등록" 한 줄로 서버를 등록한다.
#   Windows exe 는 .NET SDK 스테이지에서 빌드한다(수 분 + 네트워크 필요). 건너뛰려면: --build-arg WITH_WINDOWS=0 (그 경우 Windows 는 "서버에 없음"으로 표시)
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS winagent
ARG WITH_WINDOWS=1
ENV DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
WORKDIR /w
COPY windows-agent/Directory.Build.props windows-agent/
COPY windows-agent/src windows-agent/src
RUN mkdir -p /out \
 && if [ "$WITH_WINDOWS" = "1" ]; then \
      dotnet publish windows-agent/src/Swinventory.Agent -c Release -r win-x64 --self-contained \
        -p:PublishSingleFile=true -p:PublishTrimmed=true -p:EnableCompressionInSingleFile=true -o /pub \
      && cp /pub/swinventory-agent.exe /out/swinventory-agent-win-x64.exe; \
    fi

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 \
    SWINV_HOST=0.0.0.0 SWINV_PORT=8000 SWINV_DB_URL=sqlite:////data/swinventory.db \
    SWINV_SECRET_FILE=/data/secret.key SWINV_AGENT_DIR=/opt/swinventory/agents
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY scripts/build_agent.py ./scripts/build_agent.py
COPY deploy/agent/containers-helper.sh ./deploy/agent/containers-helper.sh
COPY deploy/agent/install.sh /opt/swinventory/agents/install.sh
COPY deploy/windows/install.ps1 /opt/swinventory/agents/install.ps1
RUN pip install ".[server,postgres]" \
 && python scripts/build_agent.py --out /opt/swinventory/agents/swinventory-agent.pyz \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin swinv \
 && mkdir -p /data && chown swinv /data
COPY --from=winagent /out/ /opt/swinventory/agents/
USER swinv
# /data 에는 설정 암호화 키(secret.key)가 생긴다. 볼륨을 잃으면 저장된 AI API 키를 복호화할 수 없다(재입력 필요).
VOLUME /data
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2).status == 200 else 1)"
# 토큰과 관리자 계정이 모두 없으면 기동을 거부한다. TLS 는 리버스 프록시에서 종단하거나 --ssl-certfile/--ssl-keyfile 사용.
CMD ["python", "-m", "swinventory.server", "serve"]
