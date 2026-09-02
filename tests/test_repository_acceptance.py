from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMMITTED_DIFF_CHECK = ROOT / "scripts/check-committed-diff"


def _git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _initialize_git_repository(repository: Path, *, initial_content: str = "clean\n") -> str:
    repository.mkdir()
    _git(repository, "init", "-b", "master")
    _git(repository, "config", "user.name", "Synthetic Test")
    _git(repository, "config", "user.email", "synthetic@example.invalid")
    (repository / "tracked.txt").write_text(initial_content, encoding="utf-8", newline="\n")
    _git(repository, "add", "tracked.txt")
    _git(repository, "commit", "-m", "initial")
    return _git(repository, "rev-parse", "HEAD")


def _commit(repository: Path, *, content: str, message: str) -> str:
    (repository / "tracked.txt").write_text(content, encoding="utf-8", newline="\n")
    _git(repository, "add", "tracked.txt")
    _git(repository, "commit", "-m", message)
    return _git(repository, "rev-parse", "HEAD")


def _run_committed_diff_check(
    repository: Path,
    *,
    event_name: str | None,
    base_sha: str | None,
    head_sha: str | None,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    for name, value in {
        "SANGREP_CI_EVENT_NAME": event_name,
        "SANGREP_CI_BASE_SHA": base_sha,
        "SANGREP_CI_HEAD_SHA": head_sha,
    }.items():
        if value is None:
            environment.pop(name, None)
        else:
            environment[name] = value
    return subprocess.run(
        [str(COMMITTED_DIFF_CHECK)],
        cwd=repository,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


@pytest.mark.parametrize(
    ("script", "success_line"),
    [
        ("scripts/check-generated", "generated-check: passed\n"),
        ("scripts/check-licenses", "license-check: passed\n"),
        ("scripts/check-docs", "docs-check: passed\n"),
        ("scripts/check-dependencies", "dependency-check: passed\n"),
        ("scripts/check-package", "package-check: passed\n"),
    ],
)
def test_standalone_repository_acceptance_script_passes(
    script: str,
    success_line: str,
) -> None:
    completed = subprocess.run(
        [str(ROOT / script)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert completed.stdout == success_line


def test_required_workflow_actions_use_verified_immutable_commit_pins() -> None:
    workflow = (ROOT / ".github/workflows/check.yml").read_text(encoding="utf-8")
    uses = {
        owner: (commit, release)
        for owner, commit, release in re.findall(
            r"uses: ([a-z0-9-]+/[a-z0-9-]+)@([0-9a-f]{40}) # (v[0-9.]+)",
            workflow,
        )
    }

    assert uses == {
        "actions/checkout": ("3d3c42e5aac5ba805825da76410c181273ba90b1", "v7"),
        "actions/setup-python": ("5fda3b95a4ea91299a34e894583c3862153e4b97", "v7"),
        "astral-sh/setup-uv": ("20cfd1bf945f4377ade1205e4dbc17946fc9a30d", "v10.0.1"),
    }


def test_committed_diff_gate_rejects_whitespace_in_pull_request_range(tmp_path: Path) -> None:
    assert COMMITTED_DIFF_CHECK.is_file()
    repository = tmp_path / "repository"
    base_sha = _initialize_git_repository(repository)
    head_sha = _commit(repository, content="trailing whitespace \n", message="defect")

    completed = _run_committed_diff_check(
        repository,
        event_name="pull_request",
        base_sha=base_sha,
        head_sha=head_sha,
    )

    assert completed.returncode != 0
    assert "trailing whitespace" in completed.stdout


def test_committed_diff_gate_accepts_clean_push_range(tmp_path: Path) -> None:
    assert COMMITTED_DIFF_CHECK.is_file()
    repository = tmp_path / "repository"
    base_sha = _initialize_git_repository(repository)
    head_sha = _commit(repository, content="clean change\n", message="clean")

    completed = _run_committed_diff_check(
        repository,
        event_name="push",
        base_sha=base_sha,
        head_sha=head_sha,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert completed.stdout == "committed-diff-check: passed\n"


def test_committed_diff_gate_checks_zero_base_push_from_empty_tree(tmp_path: Path) -> None:
    assert COMMITTED_DIFF_CHECK.is_file()
    repository = tmp_path / "repository"
    head_sha = _initialize_git_repository(repository, initial_content="trailing whitespace \n")

    completed = _run_committed_diff_check(
        repository,
        event_name="push",
        base_sha="0" * 40,
        head_sha=head_sha,
    )

    assert completed.returncode != 0
    assert "trailing whitespace" in completed.stdout


def test_committed_diff_gate_rejects_invalid_or_unreachable_authority(tmp_path: Path) -> None:
    assert COMMITTED_DIFF_CHECK.is_file()
    repository = tmp_path / "repository"
    head_sha = _initialize_git_repository(repository)

    malformed = _run_committed_diff_check(
        repository,
        event_name="pull_request",
        base_sha="not-a-sha",
        head_sha=head_sha,
    )
    unreachable = _run_committed_diff_check(
        repository,
        event_name="pull_request",
        base_sha="f" * 40,
        head_sha=head_sha,
    )

    assert malformed.returncode != 0
    assert unreachable.returncode != 0
    assert "blocked" in malformed.stderr
    assert "blocked" in unreachable.stderr


def test_committed_diff_gate_skips_only_when_ci_authority_is_absent(tmp_path: Path) -> None:
    assert COMMITTED_DIFF_CHECK.is_file()
    repository = tmp_path / "repository"
    _initialize_git_repository(repository)

    completed = _run_committed_diff_check(
        repository,
        event_name=None,
        base_sha=None,
        head_sha=None,
    )

    assert completed.returncode == 0
    assert completed.stdout == "committed-diff-check: skipped local\n"
