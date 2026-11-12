"""swinventory-server CLI.

    python -m swinventory.server serve [--host 0.0.0.0 --port 8000 --ssl-certfile C --ssl-keyfile K]
    python -m swinventory.server prune --snapshot-days 90 --event-days 365 [--host-days 180]

종료 코드: 0 성공 · 2 설정/인자 오류
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Callable, Mapping, Sequence

from swinventory.server.repo.base import InventoryRepository
from swinventory.server.timeutil import normalize_ts

log = logging.getLogger("swinventory.server")


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="swinventory-server")
    sub = p.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve", help="API·화면 서버 기동")
    serve.add_argument("--host", help="기본 127.0.0.1 (SWINV_HOST). 컨테이너에서는 0.0.0.0")
    serve.add_argument("--port", type=int, help="기본 8000 (SWINV_PORT)")
    serve.add_argument("--ssl-certfile", help="TLS 인증서(PEM). 리버스 프록시 없이 직접 HTTPS 로 서빙할 때")
    serve.add_argument("--ssl-keyfile", help="TLS 개인키(PEM)")
    serve.add_argument("--proxy-headers", action="store_true", help="리버스 프록시 뒤에서 X-Forwarded-* 를 신뢰")
    serve.add_argument("--log-level", default="info")
    prune = sub.add_parser("prune", help="보존 기간을 넘긴 이력 정리(삭제). 지정한 항목만 지운다")
    prune.add_argument("--snapshot-days", type=float, help="이 일수보다 오래된 스냅샷 기록 삭제")
    prune.add_argument("--event-days", type=float, help="이 일수보다 오래된 변경 이벤트 삭제")
    prune.add_argument("--host-days", type=float, help="이 일수 동안 수집이 없는 호스트와 그 이력 전체 삭제")
    return p


def _uvicorn_run(app, **kwargs) -> None:  # noqa: ANN001
    import uvicorn  # noqa: PLC0415 - 서버 extras 에만 있다

    uvicorn.run(app, **kwargs)


def main(
    argv: Sequence[str] | None = None, *, repo: InventoryRepository | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    run: Callable[..., None] = _uvicorn_run, env: Mapping[str, str] | None = None,
) -> int:
    args = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)
    environ = os.environ if env is None else env

    if args.command == "prune":
        days = {"snapshots_before": args.snapshot_days, "events_before": args.event_days, "hosts_before": args.host_days}
        if all(v is None for v in days.values()):
            print("--snapshot-days, --event-days, --host-days 중 하나 이상을 지정해야 한다(기본값으로 지우지 않는다)", file=sys.stderr)
            return 2
        if any(v is not None and v < 0 for v in days.values()):
            print("일수는 0 이상이어야 한다", file=sys.stderr)
            return 2
        if repo is None:
            from swinventory.server.main import repo_from_env  # noqa: PLC0415

            repo = repo_from_env(environ)
        current = now()
        cutoffs = {k: (normalize_ts(current - timedelta(days=v)) if v is not None else None) for k, v in days.items()}
        print(json.dumps(repo.prune(**cutoffs)))
        return 0

    # serve
    if bool(args.ssl_certfile) != bool(args.ssl_keyfile):
        print("--ssl-certfile 과 --ssl-keyfile 은 함께 지정해야 한다", file=sys.stderr)
        return 2
    from swinventory.server.main import create_app_from_env  # noqa: PLC0415

    try:
        app = create_app_from_env(environ)
    except (SystemExit, ValueError) as exc:  # 인증 설정 오류: 기본 계정 없이 기동하지 않는다
        print(exc, file=sys.stderr)
        return 2
    kwargs = {"host": args.host or environ.get("SWINV_HOST", "127.0.0.1"),
              "port": args.port or int(environ.get("SWINV_PORT", "8000")),
              "proxy_headers": args.proxy_headers, "log_level": args.log_level}
    if args.ssl_certfile:
        kwargs.update(ssl_certfile=args.ssl_certfile, ssl_keyfile=args.ssl_keyfile)
    run(app, **kwargs)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
