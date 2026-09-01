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
from pack_v1_fixtures import canonical_subset_sha256, parser_manifest_json

from sangrep_contracts import ContractValidationError
from sangrep_contracts.pack import SangrepPackManifestV1
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


def _signed_manifest_json() -> tuple[dict[str, object], bytes, str]:
    private_key, public_key, key_id = _synthetic_key()
    payload = parser_manifest_json()
    signature = payload["signature"]
    assert isinstance(signature, dict)
    envelope = signature["unsignedEnvelope"]
    assert isinstance(envelope, dict)
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
                "publisherId": "sangrep",
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
