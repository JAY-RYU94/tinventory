from __future__ import annotations

from swinventory.agent.collectors.os_info import OS_RELEASE_PATH, linux_family, parse_os_release
from swinventory.agent.profiles.base import PlatformProfile, UnsupportedPlatformError
from swinventory.agent.profiles.linux import DebianProfile, RhelProfile
from swinventory.agent.profiles.windows import WindowsProfile
from swinventory.agent.runtime.command import CommandRunner
from swinventory.agent.runtime.fs import FileReader
from swinventory.agent.runtime.registry import RegistryReader


def detect_profile(
    *, fs: FileReader, runner: CommandRunner,
    registry: RegistryReader | None = None, system: str = "Linux",
) -> PlatformProfile:
    """system 은 platform.system() 값. 의존성은 모두 주입받는다."""
    if system.lower() == "windows":
        if registry is None:
            raise ValueError("Windows 에서는 registry 가 필요하다")
        return WindowsProfile(runner, registry)
    try:
        info = parse_os_release(fs.read_text(OS_RELEASE_PATH))
    except FileNotFoundError as exc:
        raise UnsupportedPlatformError(f"{OS_RELEASE_PATH} 가 없다") from exc
    family = linux_family(info)
    if family == "debian":
        return DebianProfile(fs, runner)
    if family == "rhel":
        return RhelProfile(fs, runner)
    raise UnsupportedPlatformError(f"지원하지 않는 배포판: ID={info.get('ID')!r}")
