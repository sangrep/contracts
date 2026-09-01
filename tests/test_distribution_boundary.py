from __future__ import annotations

import ast
import tomllib
from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PACKAGE_ROOT / "src" / "sangrep_contracts"


def test_issue_33_allowed_contract_modules_are_explicit() -> None:
    module_names = {path.name for path in SOURCE_ROOT.glob("*.py")}

    assert module_names <= {
        "__init__.py",
        "canonical.py",
        "citation.py",
        "filesystem.py",
        "hierarchy.py",
        "identity.py",
        "pack.py",
        "pack_signing.py",
    }


ALLOWED_ABSOLUTE_IMPORT_ROOTS = frozenset(
    {
        "__future__",
        "base64",
        "binascii",
        "collections",
        "dataclasses",
        "datetime",
        "enum",
        "hashlib",
        "json",
        "re",
        "typing",
        "unicodedata",
    }
)


def test_distribution_has_no_runtime_dependencies_and_apache_license() -> None:
    project = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert project["project"]["name"] == "sangrep-contracts"
    assert project["project"]["version"] == "0.1.0.dev0"
    assert project["project"]["requires-python"] == ">=3.11"
    assert project["project"]["dependencies"] == []
    assert project["project"]["license"] == "Apache-2.0"
    assert project["project"]["license-files"] == ["LICENSE"]
    assert (SOURCE_ROOT / "py.typed").read_bytes() == b""


def test_distribution_does_not_import_product_or_effectful_runtime_modules() -> None:
    violations: list[str] = []
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names: tuple[str, ...] = ()
            if isinstance(node, ast.Import):
                names = tuple(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.level > 0:
                continue
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                names = (node.module,)
            for name in names:
                root = name.split(".", 1)[0]
                if root not in ALLOWED_ABSOLUTE_IMPORT_ROOTS:
                    violations.append(f"{path.relative_to(PACKAGE_ROOT)}:{node.lineno}:{name}")

    assert violations == []


def test_configured_hatch_force_includes_have_reproducible_sources() -> None:
    project = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    force_include = (
        project.get("tool", {})
        .get("hatch", {})
        .get("build", {})
        .get("targets", {})
        .get("wheel", {})
        .get("force-include", {})
    )

    missing_sources = [source for source in force_include if not (PACKAGE_ROOT / source).exists()]

    assert missing_sources == []


def test_wheel_includes_schemas_vectors_and_development_public_roots() -> None:
    project = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    force_include = project["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]

    assert force_include == {
        "schemas": "sangrep_contracts/schemas",
        "vectors": "sangrep_contracts/vectors",
        "trust": "sangrep_contracts/trust",
    }
