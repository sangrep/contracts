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
    SemanticVersionV1,
    manifest_sha256_v1,
    verify_catalog_dependency_graph_v1,
    verify_manifest_activation_v1,
    verify_manifest_artifact_digests_v1,
    verify_manifest_compatibility_v1,
)


def _rebind_manifest_sha(payload: dict[str, object]) -> None:
    signature = payload["signature"]
    assert isinstance(signature, dict)
    envelope = signature["unsignedEnvelope"]
    assert isinstance(envelope, dict)
    envelope["manifestSha256"] = canonical_subset_sha256(
        {key: item for key, item in payload.items() if key != "signature"}
    )


def _rebind_compatibility(payload: dict[str, object]) -> None:
    compatibility = payload["compatibility"]
    assert isinstance(compatibility, dict)
    compatibility_sha256 = canonical_subset_sha256(compatibility)
    digests = payload["digests"]
    assert isinstance(digests, dict)
    digests["compatibilityContractSha256"] = compatibility_sha256
    signature = payload["signature"]
    assert isinstance(signature, dict)
    envelope = signature["unsignedEnvelope"]
    assert isinstance(envelope, dict)
    envelope["compatibilityContractSha256"] = compatibility_sha256
    _rebind_manifest_sha(payload)


def test_manifest_round_trips_and_binds_compatibility_and_receipt_digests() -> None:
    payload = parser_manifest_json()

    manifest = SangrepPackManifestV1.from_json_obj(payload)

    assert manifest.to_json_obj() == payload
    assert manifest.pack_id == "sangrep.text-core"
    assert (
        manifest_sha256_v1(manifest) == payload["signature"]["unsignedEnvelope"]["manifestSha256"]
    )


def test_manifest_preserves_schema_valid_non_nfc_text_for_rfc8785_hashing() -> None:
    payload = parser_manifest_json()
    limitations = payload["limitations"]
    assert isinstance(limitations, list)
    limitations[0] = "Synthetic cafe\u0301 limitation."
    _rebind_manifest_sha(payload)

    manifest = SangrepPackManifestV1.from_json_obj(payload)

    assert manifest.to_json_obj() == payload
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


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("noticePath", "../NOTICE"),
        ("noticePath", "a/../../NOTICE"),
        ("licensePaths", ["."]),
        ("licensePaths", ["licenses/../LICENSE"]),
    ],
)
def test_pack_owned_license_paths_reject_dot_and_parent_segments(
    field_name: str,
    value: object,
) -> None:
    payload = parser_manifest_json()
    license_payload = payload["license"]
    assert isinstance(license_payload, dict)
    license_payload[field_name] = value
    _rebind_manifest_sha(payload)

    with pytest.raises(ContractValidationError, match="safe relative path"):
        SangrepPackManifestV1.from_json_obj(payload)


def test_remote_permissions_must_be_required() -> None:
    payload = intelligence_manifest_json()
    permissions = payload["permissions"]
    assert isinstance(permissions, dict)
    grants = permissions["grants"]
    assert isinstance(grants, list)
    grants.extend(
        [
            {
                "permission": "network.connect",
                "required": False,
                "reason": "Synthetic optional network grant.",
            },
            {
                "permission": "provider.invoke",
                "required": False,
                "reason": "Synthetic optional provider grant.",
            },
        ]
    )
    _rebind_manifest_sha(payload)

    with pytest.raises(ContractValidationError, match="required network.connect"):
        SangrepPackManifestV1.from_json_obj(payload)


def test_parser_source_read_permission_must_be_required() -> None:
    payload = parser_manifest_json()
    permissions = payload["permissions"]
    assert isinstance(permissions, dict)
    grants = permissions["grants"]
    assert isinstance(grants, list)
    source_read = grants[0]
    assert isinstance(source_read, dict)
    source_read["required"] = False
    _rebind_manifest_sha(payload)

    with pytest.raises(ContractValidationError, match="required source.read"):
        SangrepPackManifestV1.from_json_obj(payload)


def test_local_pack_rejects_network_permissions() -> None:
    payload = parser_manifest_json()
    permissions = payload["permissions"]
    assert isinstance(permissions, dict)
    grants = permissions["grants"]
    assert isinstance(grants, list)
    grants.append(
        {
            "permission": "network.connect",
            "required": True,
            "reason": "Contradictory local network grant.",
        }
    )
    _rebind_manifest_sha(payload)

    with pytest.raises(ContractValidationError, match="local packs must not declare"):
        SangrepPackManifestV1.from_json_obj(payload)


def test_remote_mode_requires_remote_isolation_profile() -> None:
    payload = intelligence_manifest_json()
    permissions = payload["permissions"]
    assert isinstance(permissions, dict)
    grants = permissions["grants"]
    assert isinstance(grants, list)
    grants.extend(
        [
            {
                "permission": "network.connect",
                "required": True,
                "reason": "Reach the synthetic endpoint.",
            },
            {
                "permission": "provider.invoke",
                "required": True,
                "reason": "Invoke the synthetic provider.",
            },
        ]
    )
    execution = payload["execution"]
    assert isinstance(execution, dict)
    execution["isolationProfile"] = "processSandboxV1"
    _rebind_manifest_sha(payload)

    with pytest.raises(ContractValidationError, match="remote mode requires remoteServiceV1"):
        SangrepPackManifestV1.from_json_obj(payload)


@pytest.mark.parametrize("reverse_entries", [False, True])
def test_platform_compatibility_rejects_overlapping_os_architecture_ranges(
    reverse_entries: bool,
) -> None:
    payload = parser_manifest_json()
    compatibility = payload["compatibility"]
    assert isinstance(compatibility, dict)
    operating_systems = compatibility["operatingSystems"]
    assert isinstance(operating_systems, list)
    operating_systems.append(
        {
            "name": "macos",
            "architectures": ["arm64"],
            "minimumInclusive": "14.0.0",
            "maximumExclusive": "16.0.0",
        }
    )
    if reverse_entries:
        operating_systems.reverse()
    _rebind_compatibility(payload)

    with pytest.raises(ContractValidationError, match="duplicate operating-system architecture"):
        SangrepPackManifestV1.from_json_obj(payload)


@pytest.mark.parametrize(
    "value",
    [
        f"{'9' * 5000}.0.0",
        "9007199254740992.0.0",
        "1.0.0-9007199254740992",
    ],
)
def test_semantic_version_parsing_rejects_oversized_numeric_components_with_typed_error(
    value: str,
) -> None:
    with pytest.raises(ContractValidationError, match="semantic version"):
        SemanticVersionV1.parse(value, field_name="semantic version")
