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


def test_installer_release_publishes_verifiable_release_artifacts() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "${{ steps.release_artifacts.outputs.linux_sha_path }}" in text
    assert ".sbom.spdx.json" in text
    assert ".release-manifest.json" in text
    assert "actions/attest-build-provenance@" in text
    assert ".virustotal.json" in text


def test_release_job_limits_write_permissions_to_the_publishing_job() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert "permissions:\n  contents: read" in text
    assert "attestations: write" in text
    assert "id-token: write" in text
