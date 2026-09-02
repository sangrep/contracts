from __future__ import annotations

import base64
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from sangrep_contracts import ContractValidationError, JsonValue, rfc8785_json_sha256_v1
from sangrep_contracts.pack import (
    SangrepPackCatalogV1,
    SangrepPackManifestV1,
    verify_catalog_dependency_graph_v1,
    verify_manifest_artifact_digests_v1,
    verify_manifest_compatibility_v1,
)
from sangrep_contracts.pack_signing import (
    BuildProfileV1,
    SangrepCatalogSignatureV1,
    SangrepPackSignatureV1,
    SangrepPackTrustRootsV1,
    SangrepPackUnsignedEnvelopeV1,
    catalog_signature_message_v1,
    pack_signature_message_v1,
    unsigned_envelope_from_canonical_json_bytes_v1,
    verify_catalog_signature_v1,
    verify_pack_signature_v1,
    verify_trust_policy_successor_v1,
)

ROOT = Path(__file__).resolve().parents[1]
MANIFEST_SCHEMA_PATH = ROOT / "schemas/sangrep-pack-manifest-v1.json"
SIGNATURE_SCHEMA_PATH = ROOT / "schemas/sangrep-pack-signature-v1.json"
MANIFEST_VECTORS_PATH = ROOT / "vectors/v1/pack-manifest.json"
SIGNING_VECTORS_PATH = ROOT / "vectors/v1/pack-signing.json"
TRUST_ROOTS_PATH = ROOT / "trust/development-pack-roots-v1.json"
VERIFICATION_TIME = datetime(2026, 9, 2, 0, 0, tzinfo=UTC)


def _load(path: Path) -> dict[str, object]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _schema_registry() -> tuple[dict[str, object], dict[str, object], Registry]:
    manifest_schema = _load(MANIFEST_SCHEMA_PATH)
    signature_schema = _load(SIGNATURE_SCHEMA_PATH)
    Draft202012Validator.check_schema(manifest_schema)
    Draft202012Validator.check_schema(signature_schema)
    registry = Registry().with_resources(
        [
            (cast(str, manifest_schema["$id"]), Resource.from_contents(manifest_schema)),
            (cast(str, signature_schema["$id"]), Resource.from_contents(signature_schema)),
        ]
    )
    return manifest_schema, signature_schema, registry


def _validator(
    schema: dict[str, object], registry: Registry, *, definition: str | None = None
) -> Draft202012Validator:
    selected: dict[str, object]
    if definition is None:
        selected = schema
    else:
        selected = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$ref": f"{schema['$id']}#/$defs/{definition}",
        }
    return Draft202012Validator(selected, registry=registry)


def _real_verifier(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except InvalidSignature:
        return False
    return True


def test_pack_schemas_are_draft_2020_12_and_positive_vectors_conform() -> None:
    manifest_schema, _, registry = _schema_registry()
    vectors = _load(MANIFEST_VECTORS_PATH)
    positive_cases = vectors["positiveCases"]
    assert isinstance(positive_cases, list)
    assert {case["name"] for case in positive_cases} == {
        "development-parser-pack",
        "development-parser-pack-non-nfc",
        "remote-intelligence-pack",
        "development-catalog",
    }

    for case in positive_cases:
        assert isinstance(case, dict)
        value = case["value"]
        contract = case["contract"]
        if contract == "manifest":
            _validator(manifest_schema, registry).validate(value)
            SangrepPackManifestV1.from_json_obj(value)
        elif contract == "catalog":
            _validator(manifest_schema, registry, definition="SangrepPackCatalogV1").validate(value)
            catalog = SangrepPackCatalogV1.from_json_obj(value)
            verify_catalog_dependency_graph_v1(catalog)
        else:
            raise AssertionError(f"unknown positive contract: {contract}")
        assert rfc8785_json_sha256_v1(cast(JsonValue, value)) == case["canonicalSha256"]


def test_manifest_malicious_vectors_cover_required_rejections() -> None:
    manifest_schema, _, registry = _schema_registry()
    cases = _load(MANIFEST_VECTORS_PATH)["negativeCases"]
    assert isinstance(cases, list)
    assert {case["name"] for case in cases} == {
        "unknown-field",
        "wrong-archive-digest",
        "incompatible-application-version",
        "local-network-permission",
        "optional-parser-source-read",
        "optional-remote-permissions",
        "overlapping-platform-range-order-a",
        "overlapping-platform-range-order-b",
        "oversized-semantic-version",
        "permission-reason-over-schema-maximum",
        "undeclared-network-permissions",
        "dependency-cycle",
        "dot-segment-license-path",
        "absent-sbom",
        "absent-license",
        "parent-segment-notice-path",
        "publisher-identity-mismatch",
        "remote-isolation-profile-mismatch",
    }

    for case in cases:
        assert isinstance(case, dict)
        operation = case["operation"]
        value = case["value"]
        if operation == "schema-manifest":
            assert list(_validator(manifest_schema, registry).iter_errors(value))
        elif operation == "manifest-runtime":
            with pytest.raises(ContractValidationError):
                SangrepPackManifestV1.from_json_obj(value)
        elif operation == "artifact-digests":
            manifest = SangrepPackManifestV1.from_json_obj(value)
            actual = case["actualDigests"]
            assert isinstance(actual, dict)
            with pytest.raises(ContractValidationError):
                verify_manifest_artifact_digests_v1(
                    manifest,
                    archive_sha256=cast(str, actual["archiveSha256"]),
                    payload_tree_sha256=cast(str, actual["payloadTreeSha256"]),
                    sbom_sha256=cast(str, actual["sbomSha256"]),
                    license_bundle_sha256=cast(str, actual["licenseBundleSha256"]),
                    conformance_receipt_sha256=cast(str, actual["conformanceReceiptSha256"]),
                )
        elif operation == "compatibility":
            manifest = SangrepPackManifestV1.from_json_obj(value)
            environment = case["environment"]
            assert isinstance(environment, dict)
            with pytest.raises(ContractValidationError):
                verify_manifest_compatibility_v1(
                    manifest,
                    contracts_version=cast(str, environment["contractsVersion"]),
                    application_version=cast(str, environment["applicationVersion"]),
                    operating_system=cast(str, environment["operatingSystem"]),
                    architecture=cast(str, environment["architecture"]),
                    operating_system_version=cast(str, environment["operatingSystemVersion"]),
                )
        elif operation == "catalog-dependencies":
            catalog = SangrepPackCatalogV1.from_json_obj(value)
            with pytest.raises(ContractValidationError):
                verify_catalog_dependency_graph_v1(catalog)
        else:
            raise AssertionError(f"unknown negative operation: {operation}")


def test_development_registry_is_exact_accepted_public_root_and_development_only() -> None:
    _, signature_schema, registry = _schema_registry()
    payload = _load(TRUST_ROOTS_PATH)
    _validator(signature_schema, registry, definition="SangrepPackTrustRootsV1").validate(payload)

    roots = SangrepPackTrustRootsV1.from_json_obj(payload)

    assert roots.trust_policy_version == 1
    assert len(roots.roots) == 1
    root = roots.roots[0]
    assert root.key_id == (
        "ed25519-sha256:348e4c2ff80ac926c23ceb273dbac9052794fb75ae3657c8d378872cc931b5c2"
    )
    assert base64.b64encode(root.public_key).decode("ascii") == (
        "YfyPwfVyUOOneCQAXoUZZbN2uEwD7G8UIvrkoY9eGs8="
    )
    assert tuple(channel.value for channel in root.channels) == ("development",)
    assert root.role.value == "packPublisher"
    assert roots.rotations == ()
    assert roots.revocations == ()


def test_signing_vectors_verify_and_cover_malicious_cases() -> None:
    _, signature_schema, registry = _schema_registry()
    vectors = _load(SIGNING_VECTORS_PATH)
    positive_cases = vectors["positiveCases"]
    assert isinstance(positive_cases, list)
    assert [case["name"] for case in positive_cases] == [
        "synthetic-development-signature",
        "synthetic-development-catalog-signature",
    ]
    positive = positive_cases[0]
    manifest = SangrepPackManifestV1.from_json_obj(positive["manifest"])
    roots = SangrepPackTrustRootsV1.from_json_obj(positive["trustRoots"])
    _validator(signature_schema, registry, definition="SangrepPackSignatureV1").validate(
        manifest.to_json_obj()["signature"]
    )
    _validator(signature_schema, registry, definition="SangrepPackTrustRootsV1").validate(
        positive["trustRoots"]
    )
    verified_root = verify_pack_signature_v1(
        manifest,
        roots,
        build_profile=BuildProfileV1.DEVELOPMENT,
        verification_time=VERIFICATION_TIME,
        verifier=_real_verifier,
    )
    assert verified_root.key_id == positive["keyId"]
    signature_payload = manifest.to_json_obj()["signature"]
    signature = SangrepPackSignatureV1.from_json_obj(signature_payload)
    assert (
        rfc8785_json_sha256_v1(cast(JsonValue, signature.unsigned_envelope.to_json_obj()))
        == positive["unsignedEnvelopeSha256"]
    )
    catalog_positive = positive_cases[1]
    catalog = SangrepPackCatalogV1.from_json_obj(catalog_positive["catalog"])
    catalog_roots = SangrepPackTrustRootsV1.from_json_obj(catalog_positive["trustRoots"])
    catalog_signature_payload = catalog.to_json_obj()["signature"]
    _validator(signature_schema, registry, definition="SangrepCatalogSignatureV1").validate(
        catalog_signature_payload
    )
    catalog_root = verify_catalog_signature_v1(
        catalog,
        catalog_roots,
        build_profile=BuildProfileV1.DEVELOPMENT,
        verification_time=VERIFICATION_TIME,
        verifier=_real_verifier,
    )
    assert catalog_root.key_id == catalog_positive["keyId"]
    catalog_signature = SangrepCatalogSignatureV1.from_json_obj(catalog_signature_payload)
    assert (
        rfc8785_json_sha256_v1(cast(JsonValue, catalog_signature.unsigned_envelope.to_json_obj()))
        == catalog_positive["unsignedEnvelopeSha256"]
    )
    assert catalog_signature_message_v1(catalog_signature.unsigned_envelope).startswith(
        b"SANGREP-CATALOG-SIGNATURE-V1\x00"
    )

    negative_cases = vectors["negativeCases"]
    assert isinstance(negative_cases, list)
    assert {case["name"] for case in negative_cases} == {
        "noncanonical-json",
        "oversized-envelope-integer",
        "noncanonical-base64",
        "digest-change-manifest",
        "digest-change-archive",
        "digest-change-payload-tree",
        "digest-change-sbom",
        "digest-change-license-bundle",
        "digest-change-conformance-receipt",
        "digest-change-compatibility-contract",
        "invalid-ed25519-signature",
        "catalog-byte-tamper",
        "catalog-pack-publisher-role-confusion",
        "role-confusion",
        "development-root-release-build",
        "unknown-root",
        "revoked-key",
        "rollback-revoked-artifact",
        "successor-authority-expansion",
        "unbounded-rotation",
    }
    for case in negative_cases:
        assert isinstance(case, dict)
        operation = case["operation"]
        if operation == "canonical-envelope-bytes":
            encoded = base64.b64decode(cast(str, case["bytesBase64"]), validate=True)
            with pytest.raises(ContractValidationError):
                unsigned_envelope_from_canonical_json_bytes_v1(encoded)
        elif operation == "signature-object":
            with pytest.raises(ContractValidationError):
                SangrepPackSignatureV1.from_json_obj(case["signature"])
        elif operation == "crypto-envelope":
            envelope = SangrepPackUnsignedEnvelopeV1.from_json_obj(case["envelope"])
            public_key = base64.b64decode(cast(str, case["publicKey"]), validate=True)
            signature_bytes = base64.b64decode(cast(str, case["signatureBase64"]), validate=True)
            assert not _real_verifier(
                public_key, signature_bytes, pack_signature_message_v1(envelope)
            )
        elif operation == "policy":
            manifest = SangrepPackManifestV1.from_json_obj(case["manifest"])
            roots = SangrepPackTrustRootsV1.from_json_obj(case["trustRoots"])
            with pytest.raises(ContractValidationError):
                verify_pack_signature_v1(
                    manifest,
                    roots,
                    build_profile=BuildProfileV1(cast(str, case["buildProfile"])),
                    verification_time=VERIFICATION_TIME,
                    verifier=_real_verifier,
                )
        elif operation == "catalog-object":
            with pytest.raises(ContractValidationError):
                SangrepPackCatalogV1.from_json_obj(case["catalog"])
        elif operation == "catalog-policy":
            catalog = SangrepPackCatalogV1.from_json_obj(case["catalog"])
            roots = SangrepPackTrustRootsV1.from_json_obj(case["trustRoots"])
            with pytest.raises(ContractValidationError):
                verify_catalog_signature_v1(
                    catalog,
                    roots,
                    build_profile=BuildProfileV1(cast(str, case["buildProfile"])),
                    verification_time=VERIFICATION_TIME,
                    verifier=_real_verifier,
                )
        elif operation == "trust-registry":
            with pytest.raises(ContractValidationError):
                SangrepPackTrustRootsV1.from_json_obj(case["trustRoots"])
        elif operation == "trust-successor":
            previous = SangrepPackTrustRootsV1.from_json_obj(case["previousTrustRoots"])
            current = SangrepPackTrustRootsV1.from_json_obj(case["currentTrustRoots"])
            with pytest.raises(ContractValidationError):
                verify_trust_policy_successor_v1(previous, current)
        else:
            raise AssertionError(f"unknown signing operation: {operation}")
