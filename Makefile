.PHONY: test test-pg build-agent agents up down demo windows-test windows-publish windows-e2e pwsh-image ansible-e2e k8s-e2e
PY ?= .venv/bin/python

test:            ## 전체 테스트(SQLite)
	$(PY) -m pytest -q

test-pg:         ## PostgreSQL 로 서버 테스트 (SWINV_TEST_DB_URL 필요, DB 이름에 test 포함)
	SWINV_TEST_DB_URL=$(SWINV_TEST_DB_URL) $(PY) -m pytest -q tests/server

build-agent:     ## dist/swinventory-agent.pyz (대상 서버에는 python3 만 있으면 된다)
	$(PY) scripts/build_agent.py

up:              ## 서버 + PostgreSQL 기동 (.env 필요)
	docker compose up -d --build

down:
	docker compose down

agents:          ## 서버가 배포할 에이전트·설치 스크립트 디렉터리 dist/agents (SWINV_AGENT_DIR)
	$(PY) scripts/prepare_agents.py

demo: agents     ## 가상 데이터로 화면 확인: http://127.0.0.1:8000 (토큰 demo). 서버 등록 화면도 동작한다
	rm -f demo.db && PYTHONPATH=src $(PY) scripts/seed_demo.py --db sqlite:///demo.db
	SWINV_AGENT_DIR=dist/agents SWINV_INGEST_TOKENS=demo-ingest SWINV_DB_URL=sqlite:///demo.db SWINV_READ_TOKENS=demo SWINV_ADMIN_TOKENS=demo-admin SWINV_STALE_AFTER_HOURS=12 \
	  $(PY) -m swinventory.server serve --port 8000

windows-test:    ## C# Windows 에이전트 xUnit (Docker 의 .NET SDK 사용, 호스트 SDK 불필요)
	windows-agent/build.sh test

windows-publish: ## windows-agent/artifacts/win-x64/swinventory-agent.exe (self-contained 단일 파일)
	windows-agent/build.sh publish

windows-e2e:     ## C# 클라이언트 ↔ 실제 서버, Linux 트리밍 바이너리 doctor 실행 검증
	scripts/e2e_windows_agent.sh

pwsh-image:      ## install.ps1 의 다운로드·해시 검증 테스트용 PowerShell 이미지(swinv-pwsh)
	docker build -t swinv-pwsh -f tests/tools/pwsh.Dockerfile tests/tools
ansible-e2e:     ## Ansible 역할 ↔ 실제 Linux 컨테이너(SSH) 배포·멱등·제거 검증
	scripts/e2e_ansible.sh
k8s-e2e:         ## 진짜 k3s 노드에 에이전트+root 헬퍼를 설치해 클러스터·파드·권한 분리 검증
	scripts/e2e_k8s.sh
