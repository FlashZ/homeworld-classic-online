from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "installer" / "install-linux.sh"


def _bash() -> str:
    candidates = [
        r"C:\Program Files\Git\bin\bash.exe",
        r"C:\Program Files\Git\usr\bin\bash.exe",
        r"C:\msys64\usr\bin\bash.exe",
    ]
    for candidate in candidates:
        if Path(candidate).exists():
            return candidate
    bash = shutil.which("bash")
    if bash:
        return bash
    raise AssertionError("bash is required for Linux installer tests")


def _fake_game(tmp_path: Path, exe_name: str = "Homeworld.exe") -> Path:
    game = tmp_path / "game"
    game.mkdir()
    (game / exe_name).write_text("", encoding="utf-8")
    return game


def _run(args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged = os.environ.copy()
    merged.update(env or {})
    return subprocess.run(
        [_bash(), str(SCRIPT), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        env=merged,
    )


def test_help_mentions_wine_and_maps(tmp_path: Path) -> None:
    result = _run(["--help"])

    assert result.returncode == 0
    assert "--wine-prefix" in result.stdout
    assert "--install-maps" in result.stdout


def test_file_only_setup_writes_nettweak_and_kver(tmp_path: Path) -> None:
    game = _fake_game(tmp_path)
    prefix = tmp_path / "prefix"
    prefix.mkdir()

    result = _run(
        [
            "--game",
            "homeworld",
            "--game-dir",
            str(game),
            "--wine-prefix",
            str(prefix),
            "--server",
            "example.test",
            "--skip-registry",
            "--skip-maps",
            "--non-interactive",
        ]
    )

    assert result.returncode == 0, result.stdout + result.stderr
    nettweak = (game / "NetTweak.script").read_text(encoding="utf-8")
    assert "DIRSERVER_IPSTRINGS example.test" in nettweak
    assert "PATCHSERVER_IPSTRINGS example.test" in nettweak
    assert (game / "kver.kp").read_bytes() == (ROOT / "keys" / "kver.kp").read_bytes()
