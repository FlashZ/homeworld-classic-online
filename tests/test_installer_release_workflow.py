from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "installer-release.yml"


def test_installer_release_packages_linux_helper_bundle() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "RetailWONSetup-linux-$tag" in text
    assert "installer/install-linux.sh" in text
    assert "generate_cdkeys.py" in text
    assert "won_crypto.py" in text
    assert "keys/kver.kp" in text
    assert "${{ steps.linux_bundle.outputs.zip_path }}" in text
