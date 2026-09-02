from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "installer-release.yml"
ATTRIBUTES = ROOT / ".gitattributes"


def test_installer_release_packages_linux_helper_bundle() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")

    assert (ROOT / "generate_cdkeys.py").is_file()
    assert (ROOT / "won_crypto.py").is_file()
    assert (ROOT / "keys" / "kver.kp").is_file()
    assert "RetailWONSetup-linux-$tag" in text
    assert "installer/install-linux.sh" in text
    assert "generate_cdkeys.py" in text
    assert "won_crypto.py" in text
    assert "keys/kver.kp" in text
    assert "${{ steps.linux_bundle.outputs.zip_path }}" in text


def test_linux_helper_is_forced_to_lf_in_checkout_and_release_bundle() -> None:
    workflow = WORKFLOW.read_text(encoding="utf-8")
    attributes = ATTRIBUTES.read_text(encoding="utf-8")

    assert "installer/install-linux.sh text eol=lf" in attributes
    assert "$linuxHelper = [System.IO.File]::ReadAllText($linuxHelperPath) -replace \"`r?`n\", \"`n\"" in workflow
    assert "[System.IO.File]::WriteAllText($linuxHelperPath, $linuxHelper, [System.Text.UTF8Encoding]::new($false))" in workflow


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
