from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


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
