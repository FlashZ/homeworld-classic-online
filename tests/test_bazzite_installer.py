from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LINUX_SCRIPT = ROOT / "installer" / "install-linux.sh"
BAZZITE_SCRIPT = ROOT / "installer" / "install-bazzite.sh"


def _bash() -> str:
    for candidate in (
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
        r"C:\msys64\usr\bin\bash.exe",
    ):
        if Path(candidate).exists():
            return candidate
    bash = shutil.which("bash")
    if bash:
        return bash
    raise AssertionError("bash is required for Linux installer tests")


def _bash_path(path: Path) -> str:
    if os.name != "nt":
        return str(path)
    result = subprocess.run(
        [_bash(), "-lc", "cygpath -u " + shlex.quote(str(path))],
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout.strip()


def _run_linux(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    merged.update(env)
    return subprocess.run(
        [_bash(), str(LINUX_SCRIPT), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        env=merged,
    )


def test_bazzite_helper_has_guided_and_advanced_modes() -> None:
    text = BAZZITE_SCRIPT.read_text(encoding="utf-8")
    assert "Which game are you setting up?" in text
    assert "--game homeworld|cataclysm" in text
    assert "com.github.Matoking.protontricks" in text
    assert "flatpak override --user" in text
    assert r'WON_INSTALLER_WINE=\"\$WINE\"' in text

    workflow = (ROOT / ".github" / "workflows" / "installer-release.yml").read_text(encoding="utf-8")
    assert "installer/install-bazzite.sh" in workflow
    assert "installer/RetailCdKeyGen.exe" in workflow


def test_linux_helper_accepts_lowercase_homeworld_executable(tmp_path: Path) -> None:
    game = tmp_path / "game"
    game.mkdir()
    (game / "homeworld.exe").write_bytes(b"")
    prefix = tmp_path / "prefix"
    prefix.mkdir()

    result = _run_linux(
        [
            "--game", "homeworld",
            "--game-dir", _bash_path(game),
            "--wine-prefix", _bash_path(prefix),
            "--skip-registry", "--skip-maps", "--non-interactive",
        ],
        {},
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert (game / "NetTweak.script").is_file()


def test_cataclysm_writes_32_bit_and_virtual_store_registry_keys(tmp_path: Path) -> None:
    game = tmp_path / "game"
    game.mkdir()
    (game / "cataclysm.exe").write_bytes(b"")
    prefix = tmp_path / "prefix"
    prefix.mkdir()
    wine_log = tmp_path / "wine.log"
    fake_wine = tmp_path / "wine"
    fake_wine.write_text(
        "#!/usr/bin/env bash\n"
        "echo WINEPREFIX=$WINEPREFIX \"$@\" >> \"$WON_FAKE_WINE_LOG\"\n"
        "if [[ \"$1\" == \"reg\" && \"$2\" == \"query\" ]]; then exit 1; fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    fake_wine.chmod(0o755)
    key_json = (
        '[{"display_key":"GAF6-CAB4-SEX5-ZYL6-2622",'
        '"plain_key":"GAF6CAB4SEX5ZYL62622",'
        '"encrypted_key_hex":"8505E499D8C18062318DA49990D8698E",'
        '"beta":false}]'
    )

    result = _run_linux(
        [
            "--game", "cataclysm",
            "--game-dir", _bash_path(game),
            "--wine-prefix", _bash_path(prefix),
            "--skip-maps", "--force-new-key", "--non-interactive",
        ],
        {
            "WON_INSTALLER_WINE": _bash_path(fake_wine),
            "WON_FAKE_WINE_LOG": _bash_path(wine_log),
            "WON_INSTALLER_KEY_JSON": key_json,
            "WON_INSTALLER_PYTHON": _bash_path(Path(sys.executable)),
        },
    )

    assert result.returncode == 0, result.stdout + result.stderr
    log = wine_log.read_text(encoding="utf-8")
    assert "reg add HKLM\\Software\\WON\\CDKeys /v Cataclysm" in log
    assert "/reg:32" in log
    assert "HKCU\\Software\\Classes\\VirtualStore\\MACHINE\\SOFTWARE\\WOW6432Node\\Sierra On-Line\\Cataclysm" in log
    assert "CataclysmOnlineSetupWroteCdKey" in log
    assert "HKLM\\Software\\Sierra On-Line\\Cataclysm\\1.0.0.0" in log
