"""print 검증이 JSON 내용을 캡처하지 않고 종료 코드만 확인하는지 검사한다."""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "deploy" / "windows" / "install.ps1"
IMAGE = "swinv-pwsh:latest"


def _have_pwsh_image() -> bool:
    return shutil.which("docker") is not None and subprocess.run(
        ["docker", "image", "inspect", IMAGE], capture_output=True
    ).returncode == 0


def test_installer_encoding_and_print_validation_contract():
    raw = INSTALLER.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf"), "Windows PowerShell 5.1 needs a UTF-8 BOM for this Korean script"

    source = raw.decode("utf-8-sig")
    assert "Invoke-PrintValidation -Executable $Exe -ConfigPath $ConfigPath" in source
    assert "ConvertFrom-Json" not in source


@pytest.mark.skipif(not _have_pwsh_image(), reason="docker 와 swinv-pwsh 이미지가 필요하다(make pwsh-image)")
def test_print_validation_discards_large_json_preserves_stderr_and_handles_failures(tmp_path):
    source = INSTALLER.read_text(encoding="utf-8-sig")
    start = source.index("function Invoke-PrintValidation(")
    end = source.index("\n}\n", start) + 3
    (tmp_path / "print-validation.ps1").write_text(source[start:end], encoding="utf-8")
    call_start = source.index("try { $printExitCode = Invoke-PrintValidation")
    call_end = source.index("\n\nif (-not $NoTask)", call_start)
    (tmp_path / "print-validation-call.ps1").write_text(source[call_start:call_end], encoding="utf-8")

    fake_agent = tmp_path / "fake-agent"
    fake_agent.write_text(
        "#!/bin/sh\n"
        "[ \"$1\" = print ] && [ \"$2\" = --config ] && [ \"$3\" = '/validation/config with spaces.json' ] || exit 97\n"
        "printf '%s' '{\"os\":{\"name\":\"한글 Windows\"},\"software\":\"JSON_SENTINEL:'\n"
        "head -c 3145728 /dev/zero | tr '\\000' x\n"
        "printf '%s\\n' '\",\"errors\":{}}'\n"
        "printf '%s\\n' 'collector warning: 수집 실패' >&2\n"
        "exit \"${FAKE_EXIT_CODE:-0}\"\n",
        encoding="utf-8",
    )
    fake_agent.chmod(0o755)
    (tmp_path / "test.ps1").write_text(
        ". /validation/print-validation.ps1\n"
        "Set-StrictMode -Version Latest\n"
        "$ErrorActionPreference = 'Stop'\n"
        "function Fail([string]$Message, [int]$Code = 1) { throw \"FAIL[$Code]: $Message\" }\n"
        "function Invoke-Scenario([string]$Executable, [string]$ExitCode) {\n"
        "  $Exe = $Executable\n"
        "  $ConfigPath = '/validation/config with spaces.json'\n"
        "  $env:FAKE_EXIT_CODE = $ExitCode\n"
        "  try {\n"
        "    . /validation/print-validation-call.ps1\n"
        "    Write-Output \"RESULT=success:$ExitCode\"\n"
        "  } catch { Write-Output \"RESULT=failure:$($_.Exception.Message)\" }\n"
        "}\n"
        "Invoke-Scenario '/validation/fake-agent' '0'\n"
        "Invoke-Scenario '/validation/fake-agent' '23'\n"
        "Invoke-Scenario '/validation/missing-agent' '0'\n",
        encoding="utf-8",
    )

    result = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{ROOT / 'deploy' / 'windows'}:/s:ro",
            "-v",
            f"{tmp_path}:/validation:ro",
            IMAGE,
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            "/validation/test.ps1",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    output = result.stdout + result.stderr
    assert result.returncode == 0, output
    assert "RESULT=success:0" in output, output
    assert "RESULT=failure:FAIL[1]: 수집이 실패했다(종료 코드 23)" in output, output
    assert "RESULT=failure:FAIL[1]: 수집 검증을 시작하지 못했다(" in output, output
    assert output.count("collector warning: 수집 실패") == 2, output
    assert "JSON_SENTINEL" not in output and "한글 Windows" not in output, output
