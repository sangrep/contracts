from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import get_type_hints

from sangrep_contracts.generated.pack_manifest_v1 import (
    SangrepPackCatalogV1Wire,
    SangrepPackManifestV1Wire,
)
from sangrep_contracts.generated.pack_signature_v1 import (
    SangrepPackSignatureV1Wire,
    SangrepPackTrustRootsV1Wire,
)

ROOT = Path(__file__).resolve().parents[1]


def test_generated_wire_types_expose_manifest_catalog_signature_and_trust_fields() -> None:
    manifest_hints = get_type_hints(SangrepPackManifestV1Wire)
    catalog_hints = get_type_hints(SangrepPackCatalogV1Wire)
    signature_hints = get_type_hints(SangrepPackSignatureV1Wire)
    roots_hints = get_type_hints(SangrepPackTrustRootsV1Wire)

    assert set(manifest_hints) == {
        "schemaVersion",
        "kind",
        "packId",
        "version",
        "family",
        "publisher",
        "channel",
        "maturity",
        "limitations",
        "formats",
        "compatibility",
        "resources",
        "execution",
        "permissions",
        "dependencies",
        "payload",
        "provenance",
        "digests",
        "license",
        "conformance",
        "signature",
    }
    assert set(catalog_hints) == {
        "schemaVersion",
        "kind",
        "catalogId",
        "version",
        "channel",
        "entries",
    }
    assert set(signature_hints) == {
        "schemaVersion",
        "kind",
        "suite",
        "role",
        "keyId",
        "unsignedEnvelope",
        "signatureBase64",
    }
    assert set(roots_hints) == {
        "schemaVersion",
        "kind",
        "trustPolicyVersion",
        "roots",
        "rotations",
        "revocations",
    }


def test_schema_type_generator_reports_no_drift() -> None:
    completed = subprocess.run(
        [sys.executable, "tools/build_schema_types.py", "--check"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert completed.stdout == "schema-type-drift: passed\n"


def test_pack_vector_generator_reports_no_drift() -> None:
    completed = subprocess.run(
        [sys.executable, "tools/build_pack_vectors.py", "--check"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert completed.stdout == "pack-vector-drift: passed\n"


def test_vector_manifest_generator_reports_no_drift() -> None:
    completed = subprocess.run(
        [sys.executable, "tools/build_vector_manifest.py", "--check"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert completed.stdout == "vector-manifest-drift: passed\n"
