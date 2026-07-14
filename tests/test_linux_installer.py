from __future__ import annotations

import os
import shutil
import shlex
import subprocess
import sys
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
            _bash_path(game),
            "--wine-prefix",
            _bash_path(prefix),
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
    assert "T1_Timeout" in nettweak
    assert "T2_Timeout" in nettweak
    assert "KEEPALIVE_SEND_IAMALIVE_TIME" in nettweak
    assert "KEEPALIVE_IAMALIVE_TIMEOUT" in nettweak
    assert (game / "kver.kp").read_bytes() == (ROOT / "keys" / "kver.kp").read_bytes()


def test_registry_write_uses_generated_key_and_selected_prefix(tmp_path: Path) -> None:
    game = _fake_game(tmp_path)
    prefix = tmp_path / "prefix"
    prefix.mkdir()
    wine_log = tmp_path / "wine.log"
    fake_wine = tmp_path / "wine"
    fake_wine.write_text(
        "#!/usr/bin/env bash\n"
        "echo WINEPREFIX=$WINEPREFIX \"$@\" >> \"$WON_FAKE_WINE_LOG\"\n"
        "if [[ \"$1\" == \"reg\" && \"$2\" == \"query\" ]]; then exit 1; fi\n"
        "if [[ \"$1\" == \"regedit\" ]]; then cat \"$2\" >> \"$WON_FAKE_WINE_LOG\"; exit 0; fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    fake_wine.chmod(0o755)

    key_json = (
        '[{"display_key":"QZK4-V7HM-3P8W-LB2T-6041",'
        '"plain_key":"QZK4V7HM3P8WLB2T6041",'
        '"encrypted_key_hex":"FB0F77C4803F65DBBBA66A4D4E2CB617",'
        '"beta":false}]'
    )

    result = _run(
        [
            "--game",
            "homeworld",
            "--game-dir",
            _bash_path(game),
            "--wine-prefix",
            _bash_path(prefix),
            "--server",
            "example.test",
            "--skip-maps",
            "--force-new-key",
            "--non-interactive",
        ],
        env={
            "WON_INSTALLER_WINE": _bash_path(fake_wine),
            "WON_FAKE_WINE_LOG": _bash_path(wine_log),
            "WON_INSTALLER_KEY_JSON": key_json,
            "WON_INSTALLER_PYTHON": _bash_path(Path(sys.executable)),
        },
    )

    assert result.returncode == 0, result.stdout + result.stderr
    log = wine_log.read_text(encoding="utf-8")
    assert f"WINEPREFIX={_bash_path(prefix)}" in log
    assert "[HKEY_LOCAL_MACHINE\\Software\\WON\\CDKeys]" in log
    assert '"Homeworld"=hex:fb,0f,77,c4,80,3f,65,db,bb,a6,6a,4d,4e,2c,b6,17' in log
    assert '"CDKey"="QZK4V7HM3P8WLB2T6041"' in log


def test_non_interactive_registry_keeps_detected_key_by_default(tmp_path: Path) -> None:
    game = _fake_game(tmp_path)
    prefix = tmp_path / "prefix"
    prefix.mkdir()
    wine_log = tmp_path / "wine.log"
    fake_wine = tmp_path / "wine"
    fake_wine.write_text(
        "#!/usr/bin/env bash\n"
        "echo WINEPREFIX=$WINEPREFIX \"$@\" >> \"$WON_FAKE_WINE_LOG\"\n"
        "if [[ \"$1\" == \"reg\" && \"$2\" == \"query\" ]]; then echo '    CDKey    REG_SZ    EXISTINGKEY'; exit 0; fi\n"
        "if [[ \"$1\" == \"regedit\" ]]; then echo SHOULD_NOT_IMPORT >> \"$WON_FAKE_WINE_LOG\"; exit 2; fi\n"
        "exit 0\n",
        encoding="utf-8",
    )
    fake_wine.chmod(0o755)

    result = _run(
        [
            "--game",
            "homeworld",
            "--game-dir",
            _bash_path(game),
            "--wine-prefix",
            _bash_path(prefix),
            "--server",
            "example.test",
            "--skip-maps",
            "--non-interactive",
        ],
        env={
            "WON_INSTALLER_WINE": _bash_path(fake_wine),
            "WON_FAKE_WINE_LOG": _bash_path(wine_log),
        },
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert "Keeping detected Homeworld CD key: EXISTINGKEY" in result.stdout
    assert "SHOULD_NOT_IMPORT" not in wine_log.read_text(encoding="utf-8")


def test_linux_helper_installs_matching_maps_from_local_archive(tmp_path: Path) -> None:
    game = _fake_game(tmp_path)
    prefix = tmp_path / "prefix"
    prefix.mkdir()
    archive_root = tmp_path / "map_repo"
    hw_map = archive_root / "Homeworld_Map_Collection-main" / "HW1_maps" / "Garden2"
    cata_map = archive_root / "Homeworld_Map_Collection-main" / "CATA_maps" / "CataOnly2"
    hw_map.mkdir(parents=True)
    cata_map.mkdir(parents=True)
    (hw_map / "Garden.level").write_text("homeworld", encoding="utf-8")
    (cata_map / "Cata.level").write_text("cataclysm", encoding="utf-8")
    archive = Path(shutil.make_archive(str(tmp_path / "maps"), "zip", archive_root))

    result = _run(
        [
            "--game",
            "homeworld",
            "--game-dir",
            _bash_path(game),
            "--wine-prefix",
            _bash_path(prefix),
            "--server",
            "example.test",
            "--skip-registry",
            "--install-maps",
            "--non-interactive",
        ],
        env={
            "WON_INSTALLER_MAP_ARCHIVE": _bash_path(archive),
            "WON_INSTALLER_PYTHON": _bash_path(Path(sys.executable)),
        },
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert (game / "MultiPlayer" / "Garden2" / "Garden.level").read_text(encoding="utf-8") == "homeworld"
    assert not (game / "MultiPlayer" / "CataOnly2").exists()
