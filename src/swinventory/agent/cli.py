"""swinventory-agent CLI.

종료 코드: 0 성공(스풀 보관 포함) · 1 수집/실행 실패 · 2 설정 오류 · 3 지원하지 않는 플랫폼
          4 서버가 영구 거절 · 5 flush 가 스풀을 다 비우지 못함
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import sys
import time
from typing import Callable, Mapping, Sequence

from swinventory.agent.config import AgentConfig, ConfigError
from swinventory.agent.orchestrator import SnapshotOrchestrator
from swinventory.agent.profiles import UnsupportedPlatformError, detect_profile
from swinventory.agent.runtime.command import CommandRunner, SubprocessRunner
from swinventory.agent.runtime.fs import FileReader, LocalFileReader
from swinventory.agent.runtime.registry import RegistryReader
from swinventory.agent.transport import (
    BaseTransport, HttpPoster, HttpsTransport, JsonFileTransport, PermanentTransportError,
    SendOutcome, SpoolingTransport, SqliteSpool, TransportError, UrllibPoster,
)

log = logging.getLogger("swinventory.agent")

EXIT_OK, EXIT_FAIL, EXIT_CONFIG, EXIT_UNSUPPORTED, EXIT_REJECTED, EXIT_FLUSH_INCOMPLETE = 0, 1, 2, 3, 4, 5


def _parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", help="JSON 설정 파일")
    common.add_argument("--server-url")
    common.add_argument("--json-dir", help="개발용: 서버 대신 디렉터리에 JSON 으로 쓴다")
    common.add_argument("--spool-path")
    common.add_argument("-v", "--verbose", action="store_true")

    p = argparse.ArgumentParser(prog="swinventory-agent", description="설치 소프트웨어·커널 버전 수집 에이전트")
    sub = p.add_subparsers(dest="command", required=True)
    sub.add_parser("collect", parents=[common], help="한 번 수집해 전송(기본)")
    sub.add_parser("print", parents=[common], help="수집 결과를 stdout 에 JSON 으로 출력(전송 안 함)")
    sub.add_parser("flush", parents=[common], help="스풀에 쌓인 항목만 재전송")
    run = sub.add_parser("run", parents=[common], help="주기적으로 수집·전송")
    run.add_argument("--interval", type=float, default=3600.0, help="초 단위 주기(기본 3600)")
    run.add_argument("--max-runs", type=int, default=None, help="이 횟수만 실행하고 종료")
    return p


def _build_transport(cfg: AgentConfig, poster: HttpPoster | None) -> BaseTransport:
    if not cfg.server_url:
        return JsonFileTransport(cfg.json_dir)  # validate() 가 json_dir 존재를 보장
    if poster is None:
        poster = UrllibPoster(cfg.ca_file, cfg.client_cert, cfg.client_key)
    https = HttpsTransport(cfg.server_url, cfg.token or "", poster, cfg.timeout)
    return SpoolingTransport(https, SqliteSpool(cfg.spool_path, cfg.spool_max_items))


def main(
    argv: Sequence[str] | None = None, *,
    fs: FileReader | None = None, runner: CommandRunner | None = None,
    registry: RegistryReader | None = None, system: str | None = None,
    poster: HttpPoster | None = None, sleep: Callable[[float], None] = time.sleep,
    env: Mapping[str, str] | None = None,
) -> int:
    """모든 외부 접근(파일·명령·레지스트리·HTTP·시계)을 주입할 수 있다(테스트용)."""
    args_in = list(sys.argv[1:] if argv is None else argv)
    if not args_in or args_in[0].startswith("-") and args_in[0] not in {"-h", "--help"}:
        args_in.insert(0, "collect")
    args = _parser().parse_args(args_in)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", stream=sys.stderr)

    environ = os.environ if env is None else env
    system = system or platform.system()
    fs, runner = fs or LocalFileReader(), runner or SubprocessRunner()
    if registry is None and system.lower() == "windows":
        from swinventory.agent.runtime.registry import WinRegistryReader  # noqa: PLC0415
        registry = WinRegistryReader()

    try:
        cfg = AgentConfig.load(args.config, environ, {
            "server_url": args.server_url, "json_dir": args.json_dir, "spool_path": args.spool_path})
        if args.command != "print":
            cfg.validate(need_server=args.command == "flush")
        transport = _build_transport(cfg, poster) if args.command != "print" else None
    except (ConfigError, OSError) as exc:  # ssl.SSLError·인증서 파일 오류 포함
        log.error("설정 오류: %s", exc)
        return EXIT_CONFIG

    def collect_once() -> int:
        try:
            profile = detect_profile(fs=fs, runner=runner, registry=registry, system=system)
        except UnsupportedPlatformError as exc:
            log.error("%s", exc)
            return EXIT_UNSUPPORTED
        try:
            snap = SnapshotOrchestrator(profile).collect()
        except Exception as exc:  # noqa: BLE001 - host_id 조회 실패 등. run 루프를 죽이지 않는다
            log.error("수집 실패: %s: %s", type(exc).__name__, exc)
            return EXIT_FAIL
        for name, err in snap.errors.items():
            log.warning("수집기 실패(계속 진행): %s: %s", name, err)
        if transport is None:
            json.dump(snap.to_dict(), sys.stdout, ensure_ascii=False, indent=2)
            sys.stdout.write("\n")
            return EXIT_OK
        try:
            outcome = transport.send(snap)
        except PermanentTransportError as exc:
            log.error("서버가 스냅샷을 거절했다: %s", exc)
            return EXIT_REJECTED
        except TransportError as exc:
            log.error("전송 실패: %s", exc)
            return EXIT_FAIL
        log.info("스냅샷 %s (host=%s, packages=%d, errors=%d)",
                 "전송 완료" if outcome is SendOutcome.SENT else "스풀에 보관", snap.host_id,
                 len(snap.packages), len(snap.errors))
        return EXIT_OK

    if args.command == "flush":
        assert isinstance(transport, SpoolingTransport)
        return EXIT_OK if transport.flush() else EXIT_FLUSH_INCOMPLETE
    if args.command != "run":
        return collect_once()

    worst, runs = EXIT_OK, 0
    try:
        while True:
            worst = max(worst, collect_once())
            runs += 1
            if args.max_runs is not None and runs >= args.max_runs:
                return worst
            sleep(args.interval)
    except KeyboardInterrupt:
        return worst


if __name__ == "__main__":
    raise SystemExit(main())
