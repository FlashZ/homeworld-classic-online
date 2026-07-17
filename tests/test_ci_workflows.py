from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TESTS_WORKFLOW = ROOT / ".github" / "workflows" / "tests.yml"


def test_ci_builds_the_windows_installer_for_pull_requests() -> None:
    text = TESTS_WORKFLOW.read_text(encoding="utf-8")

    assert "windows-installer-build:" in text
    assert "if: github.event_name == 'pull_request'" in text
    assert "installer\\build_installer.bat" in text


def test_ci_validates_and_starts_the_docker_compose_stack() -> None:
    text = TESTS_WORKFLOW.read_text(encoding="utf-8")

    assert "docker-compose-smoke:" in text
    assert "docker compose config --quiet" in text
    assert "docker compose up --detach --build" in text
    assert "http://127.0.0.1:8080/health" in text
    assert "http://127.0.0.1:8080/ready" in text
