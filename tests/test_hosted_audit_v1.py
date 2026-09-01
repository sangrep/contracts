from __future__ import annotations

import importlib.util
import sys
from importlib.machinery import SourceFileLoader
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

from public_boundary_policy import scan_bytes  # noqa: E402

RUNNER_HOME = b"/" + b"home" + b"/" + b"runner" + b"/"
USER_HOME = b"/" + b"Users" + b"/"


def _load_hosted_audit() -> ModuleType:
    loader = SourceFileLoader(
        "sangrep_hosted_audit_test",
        str(SCRIPTS / "audit-public-hosted-metadata"),
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "path",
    [
        RUNNER_HOME + b"work/contracts/contracts/src/example.py",
        RUNNER_HOME + b"work/_temp/example.txt",
        RUNNER_HOME + b".local/share/example.txt",
    ],
)
def test_hosted_audit_projects_only_expected_github_runner_roots(path: bytes) -> None:
    audit = _load_hosted_audit()

    projected = audit._project_github_hosted_runner_paths(
        path,
        repository="sangrep/contracts",
    )

    assert RUNNER_HOME not in projected
    assert b"example" in projected
    assert scan_bytes(projected, source="projected-log") == []


def test_hosted_audit_projects_exact_checkout_root_tokens() -> None:
    audit = _load_hosted_audit()
    checkout_root = RUNNER_HOME + b"work/contracts/contracts"

    projected = audit._project_github_hosted_runner_paths(
        checkout_root + b" " + checkout_root + b"')",
        repository="sangrep/contracts",
    )

    assert RUNNER_HOME not in projected
    assert projected.count(b"repository-root") == 2


def test_hosted_audit_keeps_unknown_runner_and_user_paths_fail_closed() -> None:
    audit = _load_hosted_audit()
    payloads = (
        RUNNER_HOME + b"private/example.txt",
        RUNNER_HOME + b"work/contracts/contracts-private/example.txt",
        USER_HOME + b"example/private.txt",
    )

    for payload in payloads:
        projected = audit._project_github_hosted_runner_paths(
            payload,
            repository="sangrep/contracts",
        )
        categories = {finding.category for finding in scan_bytes(projected, source="unknown-path")}
        assert categories == {"local-absolute-path"}


def test_hosted_audit_preserves_secret_scanning_inside_projected_path() -> None:
    audit = _load_hosted_audit()
    payload = RUNNER_HOME + b"work/_temp/ghp_" + (b"a" * 24)

    projected = audit._project_github_hosted_runner_paths(
        payload,
        repository="sangrep/contracts",
    )

    categories = {finding.category for finding in scan_bytes(projected, source="secret-path")}
    assert "github-token" in categories
