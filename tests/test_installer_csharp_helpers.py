from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def _find_csc() -> str | None:
    windows_csc = (
        Path(os.environ.get("WINDIR", r"C:\Windows"))
        / "Microsoft.NET"
        / "Framework"
        / "v4.0.30319"
        / "csc.exe"
    )
    if windows_csc.exists():
        return str(windows_csc)
    return shutil.which("csc")


def test_map_pack_installer_helper_behaviour(tmp_path: Path) -> None:
    csc = _find_csc()
    if not csc:
        pytest.skip("C# compiler not available")

    exe = tmp_path / "MapPackInstallerTests.exe"
    sources = [
        str(ROOT / "installer" / "hwclient_setup_maps.cs"),
        str(ROOT / "tests" / "installer" / "MapPackInstallerTests.cs"),
    ]
    choices_source = ROOT / "installer" / "hwclient_setup_choices.cs"
    if choices_source.exists():
        sources.insert(1, str(choices_source))

    result = subprocess.run(
        [
            csc,
            "/nologo",
            "/target:exe",
            f"/out:{exe}",
            *sources,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    run = subprocess.run([str(exe)], cwd=ROOT, text=True, capture_output=True)
    assert run.returncode == 0, run.stdout + run.stderr
