"""Ed25519 pack-signing envelope and trust-root policy v1."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Self, cast

from .canonical import (
    ContractValidationError,
    FrozenJsonObjectV1,
    JsonObjectValue,
    JsonValue,
    canonical_json_bytes,
    canonical_json_sha256,
    thaw_json_object_v1,
)
from .pack import (
    PackChannelV1,
    PackFamilyV1,
    SangrepPackManifestV1,
    _exact_object,
    _freeze,
    _require_canonical_base64,
    _require_enum,
    _require_enum_value,
    _require_list,
    _require_pack_id,
    _require_string,
    _require_version,
    _safe_int,
    _schema_and_kind,
)

PACK_SIGNATURE_DOMAIN_V1 = b"SANGREP-PACK-SIGNATURE-V1\x00"
_KEY_ID = re.compile(r"ed25519-sha256:[0-9a-f]{64}\Z")
_SHA256_RECEIPT = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RFC3339_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
Ed25519VerifierV1 = Callable[[bytes, bytes, bytes], bool]


class SigningRoleV1(str, Enum):
    PACK_PUBLISHER = "packPublisher"
    CATALOG = "catalog"


class BuildProfileV1(str, Enum):
    DEVELOPMENT = "development"
    RELEASE = "release"


@dataclass(frozen=True, slots=True)
class SangrepPackUnsignedEnvelopeV1:
    pack_id: str
    version: str
    family: PackFamilyV1
    publisher_id: str
    channel: PackChannelV1
    manifest_sha256: str
    archive_sha256: str
    payload_tree_sha256: str
    sbom_sha256: str
    license_bundle_sha256: str
    conformance_receipt_sha256: str
    compatibility_contract_sha256: str
    wire: FrozenJsonObjectV1

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        payload = _exact_object(
            value,
            keys={
                "schemaVersion",
                "kind",
                "packId",
                "version",
                "family",
                "publisherId",
                "channel",
                "manifestSha256",
                "archiveSha256",
                "payloadTreeSha256",
                "sbomSha256",
                "licenseBundleSha256",
                "conformanceReceiptSha256",
                "compatibilityContractSha256",
            },
            field_name="sangrepPackUnsignedEnvelope",
        )
        _schema_and_kind(payload, kind="sangrepPackUnsignedEnvelope")

        def digest(name: str) -> str:
            text = _require_string(payload[name], field_name=name)
            if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
                raise ContractValidationError(f"{name} must be a lowercase SHA-256 value.")
            return text

        return cls(
            pack_id=_require_pack_id(payload["packId"], field_name="packId"),
            version=_require_version(payload["version"], field_name="version"),
            family=_require_enum(PackFamilyV1, payload["family"], field_name="family"),
            publisher_id=_require_pack_id(payload["publisherId"], field_name="publisherId"),
            channel=_require_enum(PackChannelV1, payload["channel"], field_name="channel"),
            manifest_sha256=digest("manifestSha256"),
            archive_sha256=digest("archiveSha256"),
            payload_tree_sha256=digest("payloadTreeSha256"),
            sbom_sha256=digest("sbomSha256"),
            license_bundle_sha256=digest("licenseBundleSha256"),
            conformance_receipt_sha256=digest("conformanceReceiptSha256"),
            compatibility_contract_sha256=digest("compatibilityContractSha256"),
            wire=_freeze(payload),
        )

    def to_json_obj(self) -> JsonObjectValue:
        return thaw_json_object_v1(self.wire)


@dataclass(frozen=True, slots=True)
class SangrepPackSignatureV1:
    suite: str
    role: SigningRoleV1
    key_id: str
    unsigned_envelope: SangrepPackUnsignedEnvelopeV1
    signature: bytes
    wire: FrozenJsonObjectV1

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        payload = _exact_object(
            value,
            keys={
                "schemaVersion",
                "kind",
                "suite",
                "role",
                "keyId",
                "unsignedEnvelope",
                "signatureBase64",
            },
            field_name="sangrepPackSignature",
        )
        _schema_and_kind(payload, kind="sangrepPackSignature")
        suite = _require_enum_value(payload["suite"], values={"Ed25519"}, field_name="suite")
        key_id = _require_key_id(payload["keyId"], field_name="keyId")
        return cls(
            suite=suite,
            role=_require_enum(SigningRoleV1, payload["role"], field_name="role"),
            key_id=key_id,
            unsigned_envelope=SangrepPackUnsignedEnvelopeV1.from_json_obj(
                payload["unsignedEnvelope"]
            ),
            signature=_require_canonical_base64(
                payload["signatureBase64"], field_name="signatureBase64", decoded_bytes=64
            ),
            wire=_freeze(payload),
        )

    def to_json_obj(self) -> JsonObjectValue:
        return thaw_json_object_v1(self.wire)


@dataclass(frozen=True, slots=True)
class PackTrustRootV1:
    key_id: str
    public_key: bytes
    role: SigningRoleV1
    publisher_id: str
    channels: tuple[PackChannelV1, ...]
    custody_class: str
    receipt_digest: str
    valid_from: datetime | None
    valid_until: datetime | None


@dataclass(frozen=True, slots=True)
class PackRotationV1:
    from_key_id: str
    to_key_id: str
    overlap_starts_at: datetime
    overlap_ends_at: datetime


@dataclass(frozen=True, slots=True)
class PackRevocationV1:
    key_id: str
    revoked_at: datetime
    reason: str


@dataclass(frozen=True, slots=True)
class SangrepPackTrustRootsV1:
    trust_policy_version: int
    roots: tuple[PackTrustRootV1, ...]
    rotations: tuple[PackRotationV1, ...]
    revocations: tuple[PackRevocationV1, ...]
    wire: FrozenJsonObjectV1

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        payload = _exact_object(
            value,
            keys={
                "schemaVersion",
                "kind",
                "trustPolicyVersion",
                "roots",
                "rotations",
                "revocations",
            },
            field_name="sangrepPackTrustRoots",
        )
        _schema_and_kind(payload, kind="sangrepPackTrustRoots")
        policy_version = _safe_int(
            payload["trustPolicyVersion"], field_name="trustPolicyVersion", positive=True
        )
        roots = tuple(
            _parse_root(item, field_name=f"roots[{index}]")
            for index, item in enumerate(_require_list(payload["roots"], field_name="roots"))
        )
        if not roots:
            raise ContractValidationError("roots must not be empty.")
        roots_by_id = {root.key_id: root for root in roots}
        if len(roots_by_id) != len(roots):
            raise ContractValidationError("roots contains a duplicate keyId.")
        rotations = tuple(
            _parse_rotation(item, field_name=f"rotations[{index}]")
            for index, item in enumerate(
                _require_list(payload["rotations"], field_name="rotations")
            )
        )
        _validate_rotations(rotations, roots_by_id)
        revocations = tuple(
            _parse_revocation(item, field_name=f"revocations[{index}]")
            for index, item in enumerate(
                _require_list(payload["revocations"], field_name="revocations")
            )
        )
        revoked_ids = {item.key_id for item in revocations}
        if len(revoked_ids) != len(revocations):
            raise ContractValidationError("revocations contains a duplicate keyId.")
        if not revoked_ids <= set(roots_by_id):
            raise ContractValidationError("revocations contains an unknown keyId.")
        return cls(policy_version, roots, rotations, revocations, _freeze(payload))

    def to_json_obj(self) -> JsonObjectValue:
        return thaw_json_object_v1(self.wire)


def ed25519_key_id_v1(public_key: bytes) -> str:
    if type(public_key) is not bytes or len(public_key) != 32:
        raise ContractValidationError("Ed25519 public key must contain exactly 32 raw bytes.")
    return f"ed25519-sha256:{hashlib.sha256(public_key).hexdigest()}"


def pack_signature_message_v1(envelope: SangrepPackUnsignedEnvelopeV1) -> bytes:
    return PACK_SIGNATURE_DOMAIN_V1 + canonical_json_bytes(cast(JsonValue, envelope.to_json_obj()))


def unsigned_envelope_from_canonical_json_bytes_v1(
    data: bytes,
) -> SangrepPackUnsignedEnvelopeV1:
    if type(data) is not bytes:
        raise ContractValidationError("unsigned envelope bytes must be bytes.")

    def reject_constant(value: str) -> None:
        raise ContractValidationError(f"non-finite JSON constant is forbidden: {value}.")

    def object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ContractValidationError("unsigned envelope contains a duplicate JSON key.")
            result[key] = item
        return result

    try:
        value = json.loads(
            data.decode("utf-8"),
            parse_constant=reject_constant,
            object_pairs_hook=object_without_duplicates,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ContractValidationError("unsigned envelope is not strict UTF-8 JSON.") from error
    envelope = SangrepPackUnsignedEnvelopeV1.from_json_obj(value)
    if canonical_json_bytes(cast(JsonValue, envelope.to_json_obj())) != data:
        raise ContractValidationError("unsigned envelope bytes must use canonical RFC 8785 JSON.")
    return envelope


def verify_pack_signature_v1(
    manifest: SangrepPackManifestV1,
    trust_roots: SangrepPackTrustRootsV1,
    *,
    build_profile: BuildProfileV1,
    verification_time: datetime,
    verifier: Ed25519VerifierV1,
) -> PackTrustRootV1:
    if not isinstance(build_profile, BuildProfileV1):
        raise ContractValidationError("build_profile contains an unknown value.")
    _require_aware_utc(verification_time, field_name="verification_time")
    signature_payload = manifest.to_json_obj()["signature"]
    signature = SangrepPackSignatureV1.from_json_obj(signature_payload)
    if signature.role is not SigningRoleV1.PACK_PUBLISHER:
        raise ContractValidationError("pack signature role must be packPublisher.")
    if signature.unsigned_envelope.publisher_id != manifest.publisher_id:
        raise ContractValidationError("signature publisher identity does not match the manifest.")
    root = _resolve_root(
        trust_roots,
        signature=signature,
        manifest=manifest,
        build_profile=build_profile,
        verification_time=verification_time,
    )
    if not verifier(
        root.public_key,
        signature.signature,
        pack_signature_message_v1(signature.unsigned_envelope),
    ):
        raise ContractValidationError("Ed25519 pack signature is invalid.")
    return root


def verify_trust_policy_successor_v1(
    previous: SangrepPackTrustRootsV1,
    current: SangrepPackTrustRootsV1,
) -> None:
    if current.trust_policy_version != previous.trust_policy_version + 1:
        raise ContractValidationError("trustPolicyVersion must increase by exactly one.")
    previous_ids = {root.key_id for root in previous.roots}
    current_ids = {root.key_id for root in current.roots}
    current_revoked = {item.key_id for item in current.revocations}
    if not previous_ids <= current_ids | current_revoked:
        raise ContractValidationError("a trust root disappeared without revocation.")
    previous_revoked = {item.key_id for item in previous.revocations}
    if not previous_revoked <= current_revoked:
        raise ContractValidationError("a revoked key cannot return to trust.")


def _parse_root(value: object, *, field_name: str) -> PackTrustRootV1:
    payload = _exact_object(
        value,
        keys={
            "keyId",
            "publicKey",
            "suite",
            "role",
            "publisherId",
            "channels",
            "custodyClass",
            "receiptDigest",
            "validFrom",
            "validUntil",
        },
        field_name=field_name,
    )
    key_id = _require_key_id(payload["keyId"], field_name=f"{field_name}.keyId")
    public_key_text = _require_string(payload["publicKey"], field_name=f"{field_name}.publicKey")
    public_key = _require_canonical_base64(
        public_key_text, field_name=f"{field_name}.publicKey", decoded_bytes=32
    )
    if ed25519_key_id_v1(public_key) != key_id:
        raise ContractValidationError(f"{field_name}.keyId does not derive from publicKey.")
    _require_enum_value(payload["suite"], values={"Ed25519"}, field_name=f"{field_name}.suite")
    channels = tuple(
        _require_enum(PackChannelV1, item, field_name=f"{field_name}.channels")
        for item in _require_list(payload["channels"], field_name=f"{field_name}.channels")
    )
    if not channels or len(channels) != len(set(channels)):
        raise ContractValidationError(f"{field_name}.channels must be non-empty and unique.")
    custody_class = _require_string(
        payload["custodyClass"], field_name=f"{field_name}.custodyClass"
    )
    receipt_digest = _require_string(
        payload["receiptDigest"], field_name=f"{field_name}.receiptDigest"
    )
    if _SHA256_RECEIPT.fullmatch(receipt_digest) is None:
        raise ContractValidationError(f"{field_name}.receiptDigest must be sha256-prefixed.")
    expected_receipt = {
        "publicKey": public_key_text,
        "keyId": key_id,
        "custodyClass": custody_class,
    }
    expected_digest = f"sha256:{canonical_json_sha256(cast(JsonValue, expected_receipt))}"
    if receipt_digest != expected_digest:
        raise ContractValidationError(f"{field_name}.receiptDigest is invalid.")
    valid_from = _parse_optional_time(payload["validFrom"], field_name=f"{field_name}.validFrom")
    valid_until = _parse_optional_time(payload["validUntil"], field_name=f"{field_name}.validUntil")
    if valid_from is not None and valid_until is not None and valid_from >= valid_until:
        raise ContractValidationError(f"{field_name} validity interval must be non-empty.")
    return PackTrustRootV1(
        key_id=key_id,
        public_key=public_key,
        role=_require_enum(SigningRoleV1, payload["role"], field_name=f"{field_name}.role"),
        publisher_id=_require_pack_id(
            payload["publisherId"], field_name=f"{field_name}.publisherId"
        ),
        channels=channels,
        custody_class=custody_class,
        receipt_digest=receipt_digest,
        valid_from=valid_from,
        valid_until=valid_until,
    )


def _parse_rotation(value: object, *, field_name: str) -> PackRotationV1:
    payload = _exact_object(
        value,
        keys={"fromKeyId", "toKeyId", "overlapStartsAt", "overlapEndsAt"},
        field_name=field_name,
    )
    return PackRotationV1(
        from_key_id=_require_key_id(payload["fromKeyId"], field_name=f"{field_name}.fromKeyId"),
        to_key_id=_require_key_id(payload["toKeyId"], field_name=f"{field_name}.toKeyId"),
        overlap_starts_at=_parse_time(
            payload["overlapStartsAt"], field_name=f"{field_name}.overlapStartsAt"
        ),
        overlap_ends_at=_parse_time(
            payload["overlapEndsAt"], field_name=f"{field_name}.overlapEndsAt"
        ),
    )


def _validate_rotations(
    rotations: tuple[PackRotationV1, ...],
    roots_by_id: dict[str, PackTrustRootV1],
) -> None:
    pairs: set[tuple[str, str]] = set()
    for rotation in rotations:
        pair = (rotation.from_key_id, rotation.to_key_id)
        if pair in pairs:
            raise ContractValidationError("rotations contains a duplicate key pair.")
        pairs.add(pair)
        if rotation.from_key_id == rotation.to_key_id:
            raise ContractValidationError("rotation key IDs must differ.")
        if rotation.from_key_id not in roots_by_id or rotation.to_key_id not in roots_by_id:
            raise ContractValidationError("rotation references an unknown keyId.")
        if rotation.overlap_starts_at >= rotation.overlap_ends_at:
            raise ContractValidationError("rotation overlap must be bounded and non-empty.")
        old_root = roots_by_id[rotation.from_key_id]
        new_root = roots_by_id[rotation.to_key_id]
        if old_root.valid_until != rotation.overlap_ends_at:
            raise ContractValidationError("rotation overlapEndsAt must equal old-root validUntil.")
        if new_root.valid_from is None or new_root.valid_from > rotation.overlap_starts_at:
            raise ContractValidationError("new-root validFrom must begin by overlapStartsAt.")


def _parse_revocation(value: object, *, field_name: str) -> PackRevocationV1:
    payload = _exact_object(value, keys={"keyId", "revokedAt", "reason"}, field_name=field_name)
    return PackRevocationV1(
        key_id=_require_key_id(payload["keyId"], field_name=f"{field_name}.keyId"),
        revoked_at=_parse_time(payload["revokedAt"], field_name=f"{field_name}.revokedAt"),
        reason=_require_string(payload["reason"], field_name=f"{field_name}.reason"),
    )


def _resolve_root(
    trust_roots: SangrepPackTrustRootsV1,
    *,
    signature: SangrepPackSignatureV1,
    manifest: SangrepPackManifestV1,
    build_profile: BuildProfileV1,
    verification_time: datetime,
) -> PackTrustRootV1:
    root = next((item for item in trust_roots.roots if item.key_id == signature.key_id), None)
    if root is None:
        raise ContractValidationError("signature uses an unknown key.")
    if root.role is not signature.role:
        raise ContractValidationError("trust-root role does not match the signature role.")
    if root.publisher_id != manifest.publisher_id:
        raise ContractValidationError("trust-root publisher identity does not match the manifest.")
    if manifest.channel not in root.channels:
        raise ContractValidationError("trust root does not allow the manifest channel.")
    if build_profile is BuildProfileV1.RELEASE and (
        manifest.channel is PackChannelV1.DEVELOPMENT or PackChannelV1.DEVELOPMENT in root.channels
    ):
        raise ContractValidationError("release build rejects development manifests and roots.")
    if any(item.key_id == root.key_id for item in trust_roots.revocations):
        raise ContractValidationError("signature key is revoked.")
    if root.valid_from is not None and verification_time < root.valid_from:
        raise ContractValidationError("signature key is not yet valid.")
    if root.valid_until is not None and verification_time >= root.valid_until:
        raise ContractValidationError("signature key is expired.")
    return root


def _require_key_id(value: object, *, field_name: str) -> str:
    text = _require_string(value, field_name=field_name)
    if _KEY_ID.fullmatch(text) is None:
        raise ContractValidationError(f"{field_name} must be an Ed25519 SHA-256 key ID.")
    return text


def _parse_optional_time(value: object, *, field_name: str) -> datetime | None:
    if value is None:
        return None
    return _parse_time(value, field_name=field_name)


def _parse_time(value: object, *, field_name: str) -> datetime:
    text = _require_string(value, field_name=field_name)
    if _RFC3339_UTC.fullmatch(text) is None:
        raise ContractValidationError(f"{field_name} must be an RFC 3339 UTC second.")
    try:
        parsed = datetime.fromisoformat(text.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise ContractValidationError(f"{field_name} must be an RFC 3339 UTC second.") from error
    return parsed


def _require_aware_utc(value: datetime, *, field_name: str) -> None:
    if (
        not isinstance(value, datetime)
        or value.tzinfo is None
        or value.utcoffset() != UTC.utcoffset(value)
    ):
        raise ContractValidationError(f"{field_name} must be timezone-aware UTC.")
