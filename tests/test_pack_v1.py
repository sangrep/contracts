from __future__ import annotations

import copy

import pytest
from pack_v1_fixtures import (
    canonical_subset_sha256,
    catalog_json,
    intelligence_manifest_json,
    parser_manifest_json,
)

from sangrep_contracts import ContractValidationError
from sangrep_contracts.pack import (
    SangrepPackCatalogV1,
    SangrepPackManifestV1,
    manifest_sha256_v1,
    verify_catalog_dependency_graph_v1,
    verify_manifest_activation_v1,
    verify_manifest_artifact_digests_v1,
    verify_manifest_compatibility_v1,
)


def test_manifest_round_trips_and_binds_compatibility_and_receipt_digests() -> None:
    payload = parser_manifest_json()

    manifest = SangrepPackManifestV1.from_json_obj(payload)

    assert manifest.to_json_obj() == payload
    assert manifest.pack_id == "sangrep.text-core"
    assert (
        manifest_sha256_v1(manifest) == payload["signature"]["unsignedEnvelope"]["manifestSha256"]
    )


def test_manifest_rejects_unknown_fields() -> None:
    payload = parser_manifest_json()
    payload["unexpected"] = True

    with pytest.raises(ContractValidationError, match="missing or unknown fields"):
        SangrepPackManifestV1.from_json_obj(payload)


def test_remote_intelligence_pack_rejects_undeclared_permissions() -> None:
    payload = intelligence_manifest_json()

    with pytest.raises(ContractValidationError, match="network.connect"):
        SangrepPackManifestV1.from_json_obj(payload)


def test_compatibility_rejects_application_version_outside_range() -> None:
    manifest = SangrepPackManifestV1.from_json_obj(parser_manifest_json())

    verify_manifest_compatibility_v1(
        manifest,
        contracts_version="1.4.0",
        application_version="1.9.9",
        operating_system="macos",
        architecture="arm64",
        operating_system_version="14.2.0",
    )
    with pytest.raises(ContractValidationError, match="application version"):
        verify_manifest_compatibility_v1(
            manifest,
            contracts_version="1.4.0",
            application_version="2.0.0",
            operating_system="macos",
            architecture="arm64",
            operating_system_version="14.2.0",
        )


def test_artifact_digest_verifier_rejects_wrong_archive_digest() -> None:
    manifest = SangrepPackManifestV1.from_json_obj(parser_manifest_json())

    with pytest.raises(ContractValidationError, match="archiveSha256"):
        verify_manifest_artifact_digests_v1(
            manifest,
            archive_sha256="f" * 64,
            payload_tree_sha256="2" * 64,
            sbom_sha256="3" * 64,
            license_bundle_sha256="4" * 64,
            conformance_receipt_sha256="5" * 64,
        )


def test_catalog_dependency_graph_rejects_cycles() -> None:
    catalog = SangrepPackCatalogV1.from_json_obj(catalog_json(cyclic=True))

    with pytest.raises(ContractValidationError, match="dependency cycle"):
        verify_catalog_dependency_graph_v1(catalog)


def test_catalog_cannot_add_trust_roots() -> None:
    payload = copy.deepcopy(catalog_json())
    payload["trustRoots"] = []

    with pytest.raises(ContractValidationError, match="missing or unknown fields"):
        SangrepPackCatalogV1.from_json_obj(payload)


def test_activation_rejects_nonpassing_conformance_verdict() -> None:
    payload = parser_manifest_json()
    conformance = payload["conformance"]
    assert isinstance(conformance, dict)
    conformance["verdict"] = "notQualified"
    signature = payload["signature"]
    assert isinstance(signature, dict)
    envelope = signature["unsignedEnvelope"]
    assert isinstance(envelope, dict)
    envelope["manifestSha256"] = canonical_subset_sha256(
        {key: value for key, value in payload.items() if key != "signature"}
    )
    manifest = SangrepPackManifestV1.from_json_obj(payload)

    with pytest.raises(ContractValidationError, match="qualification verdict"):
        verify_manifest_activation_v1(manifest)
