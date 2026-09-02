from __future__ import annotations

import base64
import copy
import hashlib
import json
from datetime import UTC, datetime

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pack_v1_fixtures import canonical_subset_sha256, catalog_json, parser_manifest_json

import sangrep_contracts.pack_signing as pack_signing_module
from sangrep_contracts import (
    ContractValidationError,
    rfc8785_json_bytes_v1,
    rfc8785_json_sha256_v1,
)
from sangrep_contracts.pack import SangrepPackCatalogV1, SangrepPackManifestV1
from sangrep_contracts.pack_signing import (
    BuildProfileV1,
    SangrepPackSignatureV1,
    SangrepPackTrustRootsV1,
    SangrepPackUnsignedEnvelopeV1,
    ed25519_key_id_v1,
    pack_signature_message_v1,
    unsigned_envelope_from_canonical_json_bytes_v1,
    verify_pack_signature_v1,
    verify_trust_policy_successor_v1,
)

DOMAIN = b"SANGREP-PACK-SIGNATURE-V1\x00"
CATALOG_DOMAIN = b"SANGREP-CATALOG-SIGNATURE-V1\x00"
VERIFICATION_TIME = datetime(2026, 9, 2, 0, 0, tzinfo=UTC)


def _synthetic_key() -> tuple[Ed25519PrivateKey, bytes, str]:
    seed = hashlib.sha256(b"synthetic sangrep pack signature vector v1").digest()
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = f"ed25519-sha256:{hashlib.sha256(public_key).hexdigest()}"
    return private_key, public_key, key_id


def _synthetic_catalog_key() -> tuple[Ed25519PrivateKey, bytes, str]:
    seed = hashlib.sha256(b"synthetic sangrep catalog signature vector v1").digest()
    private_key = Ed25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    key_id = f"ed25519-sha256:{hashlib.sha256(public_key).hexdigest()}"
    return private_key, public_key, key_id


def _signed_catalog_json() -> tuple[dict[str, object], bytes, str]:
    private_key, public_key, key_id = _synthetic_catalog_key()
    catalog = catalog_json()
    catalog.pop("signature", None)
    envelope = {
        "schemaVersion": 1,
        "kind": "sangrepCatalogUnsignedEnvelope",
        "catalogId": catalog["catalogId"],
        "version": catalog["version"],
        "channel": catalog["channel"],
        "catalogSha256": rfc8785_json_sha256_v1(catalog),
    }
    signature = private_key.sign(CATALOG_DOMAIN + rfc8785_json_bytes_v1(envelope))
    catalog["signature"] = {
        "schemaVersion": 1,
        "kind": "sangrepCatalogSignature",
        "suite": "Ed25519",
        "role": "catalog",
        "keyId": key_id,
        "unsignedEnvelope": envelope,
        "signatureBase64": base64.b64encode(signature).decode("ascii"),
    }
    return catalog, public_key, key_id


def _signed_manifest_json(
    *,
    version: str = "1.0.0-dev.1",
    signer: Ed25519PrivateKey | None = None,
) -> tuple[dict[str, object], bytes, str]:
    if signer is None:
        private_key, public_key, key_id = _synthetic_key()
    else:
        private_key = signer
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        key_id = f"ed25519-sha256:{hashlib.sha256(public_key).hexdigest()}"
    payload = parser_manifest_json()
    signature = payload["signature"]
    assert isinstance(signature, dict)
    envelope = signature["unsignedEnvelope"]
    assert isinstance(envelope, dict)
    payload["version"] = version
    envelope["version"] = version
    envelope["manifestSha256"] = canonical_subset_sha256(
        {key: value for key, value in payload.items() if key != "signature"}
    )
    signature["keyId"] = key_id
    message = DOMAIN + json.dumps(
        envelope,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    signature["signatureBase64"] = base64.b64encode(private_key.sign(message)).decode("ascii")
    return payload, public_key, key_id


def _receipt_digest(public_key_text: str, key_id: str, custody_class: str) -> str:
    unsigned = {
        "custodyClass": custody_class,
        "keyId": key_id,
        "publicKey": public_key_text,
    }
    return f"sha256:{canonical_subset_sha256(unsigned)}"


def _trust_roots_json(
    public_key: bytes,
    key_id: str,
    *,
    role: str = "packPublisher",
    publisher_id: str = "sangrep",
    channels: list[str] | None = None,
    revoked: bool = False,
    valid_from: str | None = None,
    valid_until: str | None = None,
) -> dict[str, object]:
    public_key_text = base64.b64encode(public_key).decode("ascii")
    custody_class = "synthetic-test-only"
    return {
        "schemaVersion": 1,
        "kind": "sangrepPackTrustRoots",
        "trustPolicyVersion": 1,
        "roots": [
            {
                "keyId": key_id,
                "publicKey": public_key_text,
                "suite": "Ed25519",
                "role": role,
                "publisherId": publisher_id,
                "channels": channels or ["development"],
                "custodyClass": custody_class,
                "receiptDigest": _receipt_digest(public_key_text, key_id, custody_class),
                "validFrom": valid_from,
                "validUntil": valid_until,
            }
        ],
        "rotations": [],
        "revocations": (
            [
                {
                    "keyId": key_id,
                    "revokedAt": "2026-09-01T00:00:00Z",
                    "reason": "Synthetic revocation fixture.",
                }
            ]
            if revoked
            else []
        ),
    }


def test_catalog_requires_a_bound_catalog_signature() -> None:
    payload = catalog_json()
    payload.pop("signature", None)

    with pytest.raises(ContractValidationError, match="missing or unknown fields"):
        SangrepPackCatalogV1.from_json_obj(payload)


def test_catalog_signature_verifies_with_catalog_role_root() -> None:
    assert hasattr(pack_signing_module, "verify_catalog_signature_v1")
    payload, public_key, key_id = _signed_catalog_json()
    catalog = SangrepPackCatalogV1.from_json_obj(payload)
    roots = SangrepPackTrustRootsV1.from_json_obj(
        _trust_roots_json(
            public_key,
            key_id,
            role="catalog",
            publisher_id="sangrep-development",
        )
    )

    root = pack_signing_module.verify_catalog_signature_v1(
        catalog,
        roots,
        build_profile=BuildProfileV1.DEVELOPMENT,
        verification_time=VERIFICATION_TIME,
        verifier=_real_verifier,
    )

    assert root.key_id == key_id
    assert root.role.value == "catalog"


def test_catalog_signature_rejects_catalog_tamper_and_pack_publisher_role() -> None:
    assert hasattr(pack_signing_module, "verify_catalog_signature_v1")
    payload, public_key, key_id = _signed_catalog_json()
    tampered = copy.deepcopy(payload)
    entries = tampered["entries"]
    assert isinstance(entries, list)
    entry = entries[0]
    assert isinstance(entry, dict)
    entry["archiveSha256"] = "f" * 64

    with pytest.raises(ContractValidationError, match="catalogSha256"):
        SangrepPackCatalogV1.from_json_obj(tampered)

    catalog = SangrepPackCatalogV1.from_json_obj(payload)
    wrong_role_roots = SangrepPackTrustRootsV1.from_json_obj(
        _trust_roots_json(
            public_key,
            key_id,
            role="packPublisher",
            publisher_id="sangrep-development",
        )
    )
    with pytest.raises(ContractValidationError, match="role"):
        pack_signing_module.verify_catalog_signature_v1(
            catalog,
            wrong_role_roots,
            build_profile=BuildProfileV1.DEVELOPMENT,
            verification_time=VERIFICATION_TIME,
            verifier=_real_verifier,
        )


def test_pack_selection_accepts_valid_cached_reuse_and_rollback() -> None:
    assert hasattr(pack_signing_module, "PackSelectionPurposeV1")
    assert hasattr(pack_signing_module, "verify_pack_selection_v1")
    current_payload, public_key, key_id = _signed_manifest_json()
    rollback_payload, _, _ = _signed_manifest_json(version="0.9.1")
    current = SangrepPackManifestV1.from_json_obj(current_payload)
    cached = SangrepPackManifestV1.from_json_obj(copy.deepcopy(current_payload))
    rollback = SangrepPackManifestV1.from_json_obj(rollback_payload)
    roots = SangrepPackTrustRootsV1.from_json_obj(_trust_roots_json(public_key, key_id))

    cached_root = pack_signing_module.verify_pack_selection_v1(
        current,
        cached,
        roots,
        purpose=pack_signing_module.PackSelectionPurposeV1.CACHED_REUSE,
        build_profile=BuildProfileV1.DEVELOPMENT,
        verification_time=VERIFICATION_TIME,
        verifier=_real_verifier,
    )
    rollback_root = pack_signing_module.verify_pack_selection_v1(
        current,
        rollback,
        roots,
        purpose=pack_signing_module.PackSelectionPurposeV1.ROLLBACK,
        build_profile=BuildProfileV1.DEVELOPMENT,
        verification_time=VERIFICATION_TIME,
        verifier=_real_verifier,
    )

    assert cached_root.key_id == key_id
    assert rollback_root.key_id == key_id


def test_pack_selection_rejects_nonpreceding_rollback() -> None:
    assert hasattr(pack_signing_module, "PackSelectionPurposeV1")
    assert hasattr(pack_signing_module, "verify_pack_selection_v1")
    current_payload, public_key, key_id = _signed_manifest_json()
    candidate_payload, _, _ = _signed_manifest_json(version="1.1.0")
    current = SangrepPackManifestV1.from_json_obj(current_payload)
    candidate = SangrepPackManifestV1.from_json_obj(candidate_payload)
    roots = SangrepPackTrustRootsV1.from_json_obj(_trust_roots_json(public_key, key_id))

    with pytest.raises(ContractValidationError, match="precede"):
        pack_signing_module.verify_pack_selection_v1(
            current,
            candidate,
            roots,
            purpose=pack_signing_module.PackSelectionPurposeV1.ROLLBACK,
            build_profile=BuildProfileV1.DEVELOPMENT,
            verification_time=VERIFICATION_TIME,
            verifier=_real_verifier,
        )


def test_pack_selection_rejects_rollback_below_current_range() -> None:
    current_payload, public_key, key_id = _signed_manifest_json()
    candidate_payload, _, _ = _signed_manifest_json(version="0.8.9")
    current = SangrepPackManifestV1.from_json_obj(current_payload)
    candidate = SangrepPackManifestV1.from_json_obj(candidate_payload)
    roots = SangrepPackTrustRootsV1.from_json_obj(_trust_roots_json(public_key, key_id))

    with pytest.raises(ContractValidationError, match="outside"):
        pack_signing_module.verify_pack_selection_v1(
            current,
            candidate,
            roots,
            purpose=pack_signing_module.PackSelectionPurposeV1.ROLLBACK,
            build_profile=BuildProfileV1.DEVELOPMENT,
            verification_time=VERIFICATION_TIME,
            verifier=_real_verifier,
        )


def test_pack_selection_rejects_rebound_policy_from_unsigned_current_manifest() -> None:
    current_payload, public_key, key_id = _signed_manifest_json()
    candidate_payload, _, _ = _signed_manifest_json(version="0.8.9")
    rebound_current = copy.deepcopy(current_payload)
    compatibility = rebound_current["compatibility"]
    assert isinstance(compatibility, dict)
    rollback = compatibility["rollback"]
    assert isinstance(rollback, dict)
    rollback["minimumInclusive"] = "0.8.0"
    compatibility_digest = canonical_subset_sha256(compatibility)
    digests = rebound_current["digests"]
    assert isinstance(digests, dict)
    digests["compatibilityContractSha256"] = compatibility_digest
    signature = rebound_current["signature"]
    assert isinstance(signature, dict)
    envelope = signature["unsignedEnvelope"]
    assert isinstance(envelope, dict)
    envelope["compatibilityContractSha256"] = compatibility_digest
    envelope["manifestSha256"] = canonical_subset_sha256(
        {key: value for key, value in rebound_current.items() if key != "signature"}
    )
    current = SangrepPackManifestV1.from_json_obj(rebound_current)
    candidate = SangrepPackManifestV1.from_json_obj(candidate_payload)
    roots = SangrepPackTrustRootsV1.from_json_obj(_trust_roots_json(public_key, key_id))

    with pytest.raises(ContractValidationError, match="signature"):
        pack_signing_module.verify_pack_selection_v1(
            current,
            candidate,
            roots,
            purpose=pack_signing_module.PackSelectionPurposeV1.ROLLBACK,
            build_profile=BuildProfileV1.DEVELOPMENT,
            verification_time=VERIFICATION_TIME,
            verifier=_real_verifier,
        )


def test_pack_selection_revalidates_historical_artifact_under_current_denylist() -> None:
    assert hasattr(pack_signing_module, "PackSelectionPurposeV1")
    assert hasattr(pack_signing_module, "verify_pack_selection_v1")
    current_signer = Ed25519PrivateKey.from_private_bytes(
        hashlib.sha256(b"synthetic current pack selection test key v1").digest()
    )
    current_payload, current_public_key, current_key_id = _signed_manifest_json(
        signer=current_signer
    )
    candidate_payload, candidate_public_key, candidate_key_id = _signed_manifest_json(
        version="0.9.1"
    )
    current = SangrepPackManifestV1.from_json_obj(current_payload)
    candidate = SangrepPackManifestV1.from_json_obj(candidate_payload)
    historical_roots = SangrepPackTrustRootsV1.from_json_obj(
        _trust_roots_json(candidate_public_key, candidate_key_id)
    )
    current_roots_payload = _trust_roots_json(current_public_key, current_key_id)
    revoked_candidate_payload = _trust_roots_json(
        candidate_public_key,
        candidate_key_id,
        revoked=True,
    )
    current_roots = current_roots_payload["roots"]
    revoked_candidate_roots = revoked_candidate_payload["roots"]
    assert isinstance(current_roots, list)
    assert isinstance(revoked_candidate_roots, list)
    current_roots.extend(revoked_candidate_roots)
    current_roots_payload["revocations"] = revoked_candidate_payload["revocations"]
    current_trust_roots = SangrepPackTrustRootsV1.from_json_obj(current_roots_payload)

    verify_pack_signature_v1(
        current,
        current_trust_roots,
        build_profile=BuildProfileV1.DEVELOPMENT,
        verification_time=VERIFICATION_TIME,
        verifier=_real_verifier,
    )
    verify_pack_signature_v1(
        candidate,
        historical_roots,
        build_profile=BuildProfileV1.DEVELOPMENT,
        verification_time=VERIFICATION_TIME,
        verifier=_real_verifier,
    )
    with pytest.raises(ContractValidationError, match="revoked"):
        pack_signing_module.verify_pack_selection_v1(
            current,
            candidate,
            current_trust_roots,
            purpose=pack_signing_module.PackSelectionPurposeV1.ROLLBACK,
            build_profile=BuildProfileV1.DEVELOPMENT,
            verification_time=VERIFICATION_TIME,
            verifier=_real_verifier,
        )


def _real_verifier(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except InvalidSignature:
        return False
    return True


def test_key_id_and_signed_bytes_match_independent_rfc_8032_fixture() -> None:
    payload, public_key, key_id = _signed_manifest_json()
    signature_payload = payload["signature"]
    assert isinstance(signature_payload, dict)
    envelope_payload = signature_payload["unsignedEnvelope"]
    assert isinstance(envelope_payload, dict)
    envelope = SangrepPackUnsignedEnvelopeV1.from_json_obj(envelope_payload)
    expected_message = DOMAIN + json.dumps(
        envelope_payload,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    assert ed25519_key_id_v1(public_key) == key_id
    assert pack_signature_message_v1(envelope) == expected_message


def test_real_ed25519_signature_verifies_for_development_root() -> None:
    payload, public_key, key_id = _signed_manifest_json()
    manifest = SangrepPackManifestV1.from_json_obj(payload)
    roots = SangrepPackTrustRootsV1.from_json_obj(_trust_roots_json(public_key, key_id))

    root = verify_pack_signature_v1(
        manifest,
        roots,
        build_profile=BuildProfileV1.DEVELOPMENT,
        verification_time=VERIFICATION_TIME,
        verifier=_real_verifier,
    )

    assert root.key_id == key_id


def test_signature_rejects_byte_change_in_every_digest() -> None:
    payload, public_key, key_id = _signed_manifest_json()
    signature_payload = payload["signature"]
    assert isinstance(signature_payload, dict)
    original_envelope = signature_payload["unsignedEnvelope"]
    assert isinstance(original_envelope, dict)
    original_signature = SangrepPackSignatureV1.from_json_obj(signature_payload)
    digest_fields = (
        "manifestSha256",
        "archiveSha256",
        "payloadTreeSha256",
        "sbomSha256",
        "licenseBundleSha256",
        "conformanceReceiptSha256",
        "compatibilityContractSha256",
    )

    for field_name in digest_fields:
        mutated_envelope = copy.deepcopy(original_envelope)
        mutated_envelope[field_name] = "f" * 64
        if mutated_envelope[field_name] == original_envelope[field_name]:
            mutated_envelope[field_name] = "e" * 64
        envelope = SangrepPackUnsignedEnvelopeV1.from_json_obj(mutated_envelope)
        assert not _real_verifier(
            public_key,
            original_signature.signature,
            pack_signature_message_v1(envelope),
        ), field_name


def test_signature_rejects_noncanonical_base64() -> None:
    payload, _, _ = _signed_manifest_json()
    signature_payload = payload["signature"]
    assert isinstance(signature_payload, dict)
    signature_payload["signatureBase64"] = str(signature_payload["signatureBase64"]).rstrip("=")

    with pytest.raises(ContractValidationError, match="canonical base64"):
        SangrepPackSignatureV1.from_json_obj(signature_payload)


def test_unsigned_envelope_rejects_noncanonical_json_bytes() -> None:
    payload, _, _ = _signed_manifest_json()
    signature_payload = payload["signature"]
    assert isinstance(signature_payload, dict)
    envelope = signature_payload["unsignedEnvelope"]
    noncanonical = json.dumps(envelope, indent=2).encode("utf-8")

    with pytest.raises(ContractValidationError, match="canonical RFC 8785"):
        unsigned_envelope_from_canonical_json_bytes_v1(noncanonical)


def test_unsigned_envelope_bounds_bytes_and_integer_parsing_with_typed_errors() -> None:
    with pytest.raises(ContractValidationError, match="serialized byte limit"):
        unsigned_envelope_from_canonical_json_bytes_v1(b" " * 10_485_761)

    oversized_integer = b'{"schemaVersion":' + (b"9" * 5000) + b"}"
    with pytest.raises(ContractValidationError, match="I-JSON range"):
        unsigned_envelope_from_canonical_json_bytes_v1(oversized_integer)


@pytest.mark.parametrize(
    ("root_mutation", "build_profile", "message"),
    [
        ({"role": "catalog"}, BuildProfileV1.DEVELOPMENT, "role"),
        ({"unknown": True}, BuildProfileV1.DEVELOPMENT, "unknown key"),
        ({}, BuildProfileV1.RELEASE, "release build"),
        ({"revoked": True}, BuildProfileV1.DEVELOPMENT, "revoked"),
    ],
)
def test_trust_policy_rejects_role_unknown_release_and_revoked_roots(
    root_mutation: dict[str, object],
    build_profile: BuildProfileV1,
    message: str,
) -> None:
    payload, public_key, key_id = _signed_manifest_json()
    manifest = SangrepPackManifestV1.from_json_obj(payload)
    selected_key_id = key_id
    if root_mutation.get("unknown"):
        selected_key_id = f"ed25519-sha256:{'f' * 64}"
        signature_payload = payload["signature"]
        assert isinstance(signature_payload, dict)
        signature_payload["keyId"] = selected_key_id
        manifest = SangrepPackManifestV1.from_json_obj(payload)
    roots_payload = _trust_roots_json(
        public_key,
        key_id,
        role=str(root_mutation.get("role", "packPublisher")),
        revoked=bool(root_mutation.get("revoked", False)),
    )
    roots = SangrepPackTrustRootsV1.from_json_obj(roots_payload)

    with pytest.raises(ContractValidationError, match=message):
        verify_pack_signature_v1(
            manifest,
            roots,
            build_profile=build_profile,
            verification_time=VERIFICATION_TIME,
            verifier=_real_verifier,
        )
    assert selected_key_id != ""


def test_trust_registry_runtime_rejects_revocation_reason_above_schema_maximum() -> None:
    _, public_key, key_id = _signed_manifest_json()
    payload = _trust_roots_json(public_key, key_id, revoked=True)
    revocations = payload["revocations"]
    assert isinstance(revocations, list)
    revocation = revocations[0]
    assert isinstance(revocation, dict)
    revocation["reason"] = "x" * 513

    with pytest.raises(ContractValidationError, match="reason"):
        SangrepPackTrustRootsV1.from_json_obj(payload)


@pytest.mark.parametrize(
    ("valid_from", "valid_until", "message"),
    [
        ("2026-09-03T00:00:00Z", None, "not yet valid"),
        (None, "2026-09-02T00:00:00Z", "expired"),
    ],
)
def test_trust_policy_rejects_not_yet_valid_and_expired_roots(
    valid_from: str | None,
    valid_until: str | None,
    message: str,
) -> None:
    payload, public_key, key_id = _signed_manifest_json()
    manifest = SangrepPackManifestV1.from_json_obj(payload)
    roots = SangrepPackTrustRootsV1.from_json_obj(
        _trust_roots_json(
            public_key,
            key_id,
            valid_from=valid_from,
            valid_until=valid_until,
        )
    )

    with pytest.raises(ContractValidationError, match=message):
        verify_pack_signature_v1(
            manifest,
            roots,
            build_profile=BuildProfileV1.DEVELOPMENT,
            verification_time=VERIFICATION_TIME,
            verifier=_real_verifier,
        )


def test_rotation_requires_a_bounded_overlap() -> None:
    _, first_public_key, first_key_id = _signed_manifest_json()
    second_private = Ed25519PrivateKey.generate()
    second_public_key = second_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    second_key_id = f"ed25519-sha256:{hashlib.sha256(second_public_key).hexdigest()}"
    payload = _trust_roots_json(
        first_public_key,
        first_key_id,
        valid_until="2026-10-01T00:00:00Z",
    )
    second = _trust_roots_json(
        second_public_key,
        second_key_id,
        valid_from="2026-09-15T00:00:00Z",
    )["roots"][0]
    roots = payload["roots"]
    assert isinstance(roots, list)
    roots.append(second)
    payload["rotations"] = [
        {
            "fromKeyId": first_key_id,
            "toKeyId": second_key_id,
            "overlapStartsAt": "2026-09-15T00:00:00Z",
            "overlapEndsAt": "2026-10-01T00:00:00Z",
        }
    ]

    SangrepPackTrustRootsV1.from_json_obj(payload)
    rotation = payload["rotations"][0]
    assert isinstance(rotation, dict)
    rotation["overlapEndsAt"] = None
    with pytest.raises(ContractValidationError, match="overlapEndsAt"):
        SangrepPackTrustRootsV1.from_json_obj(payload)


def test_trust_policy_successor_is_monotonic_and_cannot_undo_revocation() -> None:
    _, public_key, key_id = _signed_manifest_json()
    previous_payload = _trust_roots_json(public_key, key_id, revoked=True)
    previous = SangrepPackTrustRootsV1.from_json_obj(previous_payload)
    current_payload = copy.deepcopy(previous_payload)
    current_payload["trustPolicyVersion"] = 2
    current = SangrepPackTrustRootsV1.from_json_obj(current_payload)

    verify_trust_policy_successor_v1(previous, current)

    skipped_payload = copy.deepcopy(current_payload)
    skipped_payload["trustPolicyVersion"] = 3
    skipped = SangrepPackTrustRootsV1.from_json_obj(skipped_payload)
    with pytest.raises(ContractValidationError, match="increase by exactly one"):
        verify_trust_policy_successor_v1(previous, skipped)

    restored_payload = copy.deepcopy(current_payload)
    restored_payload["revocations"] = []
    restored = SangrepPackTrustRootsV1.from_json_obj(restored_payload)
    with pytest.raises(ContractValidationError, match="cannot return"):
        verify_trust_policy_successor_v1(previous, restored)


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("role", "catalog"),
        ("publisherId", "other"),
        ("channels", ["release"]),
        ("validFrom", "2026-09-02T00:00:00Z"),
        ("validUntil", "2026-10-01T00:00:00Z"),
    ],
)
def test_trust_policy_successor_rejects_existing_root_authority_changes(
    field_name: str,
    value: object,
) -> None:
    _, public_key, key_id = _signed_manifest_json()
    previous_payload = _trust_roots_json(public_key, key_id)
    previous = SangrepPackTrustRootsV1.from_json_obj(previous_payload)
    current_payload = copy.deepcopy(previous_payload)
    current_payload["trustPolicyVersion"] = 2
    current_root = current_payload["roots"][0]
    assert isinstance(current_root, dict)
    current_root[field_name] = value
    current = SangrepPackTrustRootsV1.from_json_obj(current_payload)

    with pytest.raises(ContractValidationError, match="existing trust-root authority"):
        verify_trust_policy_successor_v1(previous, current)


def test_trust_policy_successor_requires_new_root_to_use_bounded_rotation() -> None:
    _, first_public_key, first_key_id = _signed_manifest_json()
    previous_payload = _trust_roots_json(first_public_key, first_key_id)
    previous = SangrepPackTrustRootsV1.from_json_obj(previous_payload)
    second_private = Ed25519PrivateKey.generate()
    second_public_key = second_private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    second_key_id = f"ed25519-sha256:{hashlib.sha256(second_public_key).hexdigest()}"
    current_payload = copy.deepcopy(previous_payload)
    current_payload["trustPolicyVersion"] = 2
    current_roots = current_payload["roots"]
    assert isinstance(current_roots, list)
    current_roots.append(_trust_roots_json(second_public_key, second_key_id)["roots"][0])
    current = SangrepPackTrustRootsV1.from_json_obj(current_payload)

    with pytest.raises(ContractValidationError, match="bounded rotation"):
        verify_trust_policy_successor_v1(previous, current)

    old_root = current_roots[0]
    new_root = current_roots[1]
    assert isinstance(old_root, dict)
    assert isinstance(new_root, dict)
    old_root["validUntil"] = "2026-10-01T00:00:00Z"
    new_root["validFrom"] = "2026-09-15T00:00:00Z"
    current_payload["rotations"] = [
        {
            "fromKeyId": first_key_id,
            "toKeyId": second_key_id,
            "overlapStartsAt": "2026-09-15T00:00:00Z",
            "overlapEndsAt": "2026-10-01T00:00:00Z",
        }
    ]
    rotated = SangrepPackTrustRootsV1.from_json_obj(current_payload)

    verify_trust_policy_successor_v1(previous, rotated)
