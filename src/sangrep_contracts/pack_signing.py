"""Ed25519 pack-signing envelope and trust-root policy v1."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from typing import Self, cast

from .canonical import (
    ContractValidationError,
    JsonObjectValue,
    JsonValue,
    Rfc8785JsonObjectV1,
    rfc8785_json_bytes_v1,
    rfc8785_json_object_from_bytes_v1,
    rfc8785_json_sha256_v1,
    thaw_rfc8785_json_object_v1,
)
from .pack import (
    PackChannelV1,
    PackFamilyV1,
    SangrepPackCatalogV1,
    SangrepPackManifestV1,
    SemanticVersionV1,
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
    catalog_sha256_v1,
    manifest_sha256_v1,
)
from .schema_bounds import validate_pack_schema_bounds_v1

PACK_SIGNATURE_DOMAIN_V1 = b"SANGREP-PACK-SIGNATURE-V1\x00"
CATALOG_SIGNATURE_DOMAIN_V1 = b"SANGREP-CATALOG-SIGNATURE-V1\x00"
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


class PackSelectionPurposeV1(str, Enum):
    CACHED_REUSE = "cachedReuse"
    ROLLBACK = "rollback"


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
    wire: Rfc8785JsonObjectV1

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        validate_pack_schema_bounds_v1(value, definition="SangrepPackUnsignedEnvelopeV1")
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
        return thaw_rfc8785_json_object_v1(self.wire)


@dataclass(frozen=True, slots=True)
class SangrepPackSignatureV1:
    suite: str
    role: SigningRoleV1
    key_id: str
    unsigned_envelope: SangrepPackUnsignedEnvelopeV1
    signature: bytes
    wire: Rfc8785JsonObjectV1

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        validate_pack_schema_bounds_v1(value, definition="SangrepPackSignatureV1")
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
        return thaw_rfc8785_json_object_v1(self.wire)


@dataclass(frozen=True, slots=True)
class SangrepCatalogUnsignedEnvelopeV1:
    catalog_id: str
    version: str
    channel: PackChannelV1
    catalog_sha256: str
    wire: Rfc8785JsonObjectV1

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        validate_pack_schema_bounds_v1(value, definition="SangrepCatalogUnsignedEnvelopeV1")
        payload = _exact_object(
            value,
            keys={
                "schemaVersion",
                "kind",
                "catalogId",
                "version",
                "channel",
                "catalogSha256",
            },
            field_name="sangrepCatalogUnsignedEnvelope",
        )
        _schema_and_kind(payload, kind="sangrepCatalogUnsignedEnvelope")
        return cls(
            catalog_id=_require_pack_id(payload["catalogId"], field_name="catalogId"),
            version=_require_version(payload["version"], field_name="version"),
            channel=_require_enum(PackChannelV1, payload["channel"], field_name="channel"),
            catalog_sha256=_require_sha256_value(
                payload["catalogSha256"], field_name="catalogSha256"
            ),
            wire=_freeze(payload),
        )

    def to_json_obj(self) -> JsonObjectValue:
        return thaw_rfc8785_json_object_v1(self.wire)


@dataclass(frozen=True, slots=True)
class SangrepCatalogSignatureV1:
    suite: str
    role: SigningRoleV1
    key_id: str
    unsigned_envelope: SangrepCatalogUnsignedEnvelopeV1
    signature: bytes
    wire: Rfc8785JsonObjectV1

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        validate_pack_schema_bounds_v1(value, definition="SangrepCatalogSignatureV1")
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
            field_name="sangrepCatalogSignature",
        )
        _schema_and_kind(payload, kind="sangrepCatalogSignature")
        suite = _require_enum_value(payload["suite"], values={"Ed25519"}, field_name="suite")
        role = _require_enum(SigningRoleV1, payload["role"], field_name="role")
        if role is not SigningRoleV1.CATALOG:
            raise ContractValidationError("catalog signature role must be catalog.")
        return cls(
            suite=suite,
            role=role,
            key_id=_require_key_id(payload["keyId"], field_name="keyId"),
            unsigned_envelope=SangrepCatalogUnsignedEnvelopeV1.from_json_obj(
                payload["unsignedEnvelope"]
            ),
            signature=_require_canonical_base64(
                payload["signatureBase64"], field_name="signatureBase64", decoded_bytes=64
            ),
            wire=_freeze(payload),
        )

    def to_json_obj(self) -> JsonObjectValue:
        return thaw_rfc8785_json_object_v1(self.wire)


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
    wire: Rfc8785JsonObjectV1

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        validate_pack_schema_bounds_v1(value, definition="SangrepPackTrustRootsV1")
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
        return thaw_rfc8785_json_object_v1(self.wire)


def ed25519_key_id_v1(public_key: bytes) -> str:
    if type(public_key) is not bytes or len(public_key) != 32:
        raise ContractValidationError("Ed25519 public key must contain exactly 32 raw bytes.")
    return f"ed25519-sha256:{hashlib.sha256(public_key).hexdigest()}"


def pack_signature_message_v1(envelope: SangrepPackUnsignedEnvelopeV1) -> bytes:
    return PACK_SIGNATURE_DOMAIN_V1 + rfc8785_json_bytes_v1(cast(JsonValue, envelope.to_json_obj()))


def catalog_signature_message_v1(envelope: SangrepCatalogUnsignedEnvelopeV1) -> bytes:
    return CATALOG_SIGNATURE_DOMAIN_V1 + rfc8785_json_bytes_v1(
        cast(JsonValue, envelope.to_json_obj())
    )


def unsigned_envelope_from_canonical_json_bytes_v1(
    data: bytes,
) -> SangrepPackUnsignedEnvelopeV1:
    return SangrepPackUnsignedEnvelopeV1.from_json_obj(rfc8785_json_object_from_bytes_v1(data))


def catalog_unsigned_envelope_from_canonical_json_bytes_v1(
    data: bytes,
) -> SangrepCatalogUnsignedEnvelopeV1:
    return SangrepCatalogUnsignedEnvelopeV1.from_json_obj(rfc8785_json_object_from_bytes_v1(data))


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
    root = _resolve_signing_root(
        trust_roots,
        key_id=signature.key_id,
        role=signature.role,
        publisher_id=manifest.publisher_id,
        channel=manifest.channel,
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


def verify_catalog_signature_v1(
    catalog: SangrepPackCatalogV1,
    trust_roots: SangrepPackTrustRootsV1,
    *,
    build_profile: BuildProfileV1,
    verification_time: datetime,
    verifier: Ed25519VerifierV1,
) -> PackTrustRootV1:
    if not isinstance(build_profile, BuildProfileV1):
        raise ContractValidationError("build_profile contains an unknown value.")
    _require_aware_utc(verification_time, field_name="verification_time")
    signature_payload = catalog.to_json_obj()["signature"]
    signature = SangrepCatalogSignatureV1.from_json_obj(signature_payload)
    if signature.unsigned_envelope.catalog_id != catalog.catalog_id:
        raise ContractValidationError("signature catalog identity does not match the catalog.")
    if signature.unsigned_envelope.catalog_sha256 != catalog_sha256_v1(catalog):
        raise ContractValidationError("catalogSha256 does not match the unsigned catalog.")
    root = _resolve_signing_root(
        trust_roots,
        key_id=signature.key_id,
        role=signature.role,
        publisher_id=catalog.catalog_id,
        channel=catalog.channel,
        build_profile=build_profile,
        verification_time=verification_time,
    )
    if not verifier(
        root.public_key,
        signature.signature,
        catalog_signature_message_v1(signature.unsigned_envelope),
    ):
        raise ContractValidationError("Ed25519 catalog signature is invalid.")
    return root


def verify_pack_selection_v1(
    current_manifest: SangrepPackManifestV1,
    candidate_manifest: SangrepPackManifestV1,
    current_trust_roots: SangrepPackTrustRootsV1,
    *,
    purpose: PackSelectionPurposeV1,
    build_profile: BuildProfileV1,
    verification_time: datetime,
    verifier: Ed25519VerifierV1,
) -> PackTrustRootV1:
    if not isinstance(purpose, PackSelectionPurposeV1):
        raise ContractValidationError("purpose contains an unknown pack-selection value.")
    current_identity = (
        current_manifest.pack_id,
        current_manifest.family,
        current_manifest.publisher_id,
        current_manifest.channel,
    )
    candidate_identity = (
        candidate_manifest.pack_id,
        candidate_manifest.family,
        candidate_manifest.publisher_id,
        candidate_manifest.channel,
    )
    if candidate_identity != current_identity:
        raise ContractValidationError(
            "candidate pack identity does not match the current manifest."
        )
    current_version = SemanticVersionV1.parse(
        current_manifest.version,
        field_name="current manifest version",
    )
    candidate_version = SemanticVersionV1.parse(
        candidate_manifest.version,
        field_name="candidate manifest version",
    )
    if purpose is PackSelectionPurposeV1.CACHED_REUSE:
        if candidate_version != current_version or manifest_sha256_v1(
            candidate_manifest
        ) != manifest_sha256_v1(current_manifest):
            raise ContractValidationError(
                "cached reuse requires the exact current version and manifest digest."
            )
    else:
        if not candidate_version.precedes(current_version):
            raise ContractValidationError(
                "rollback candidate version must precede current version."
            )
        if not current_manifest.compatibility.rollback.contains(candidate_version):
            raise ContractValidationError(
                "rollback candidate is outside the current rollback range."
            )
    return verify_pack_signature_v1(
        candidate_manifest,
        current_trust_roots,
        build_profile=build_profile,
        verification_time=verification_time,
        verifier=verifier,
    )


def verify_trust_policy_successor_v1(
    previous: SangrepPackTrustRootsV1,
    current: SangrepPackTrustRootsV1,
) -> None:
    if current.trust_policy_version != previous.trust_policy_version + 1:
        raise ContractValidationError("trustPolicyVersion must increase by exactly one.")
    previous_by_id = {root.key_id: root for root in previous.roots}
    current_by_id = {root.key_id: root for root in current.roots}
    previous_ids = set(previous_by_id)
    current_ids = set(current_by_id)
    if not previous_ids <= current_ids:
        raise ContractValidationError("a trust root disappeared without revocation.")
    rotations_by_from = {rotation.from_key_id: rotation for rotation in current.rotations}
    for key_id, previous_root in previous_by_id.items():
        current_root = current_by_id[key_id]
        immutable_authority = (
            previous_root.public_key,
            previous_root.role,
            previous_root.publisher_id,
            frozenset(previous_root.channels),
            previous_root.custody_class,
            previous_root.receipt_digest,
            previous_root.valid_from,
        )
        current_authority = (
            current_root.public_key,
            current_root.role,
            current_root.publisher_id,
            frozenset(current_root.channels),
            current_root.custody_class,
            current_root.receipt_digest,
            current_root.valid_from,
        )
        if current_authority != immutable_authority:
            raise ContractValidationError("existing trust-root authority cannot change.")
        if current_root.valid_until != previous_root.valid_until:
            rotation = rotations_by_from.get(key_id)
            if rotation is None or current_root.valid_until != rotation.overlap_ends_at:
                raise ContractValidationError("existing trust-root authority cannot change.")
            if (
                previous_root.valid_until is not None
                and current_root.valid_until is not None
                and current_root.valid_until > previous_root.valid_until
            ):
                raise ContractValidationError("existing trust-root validity cannot be extended.")
    rotated_new_ids = {
        rotation.to_key_id for rotation in current.rotations if rotation.from_key_id in previous_ids
    }
    if not current_ids - previous_ids <= rotated_new_ids:
        raise ContractValidationError("new trust roots require a bounded rotation.")
    previous_rotations = {
        (rotation.from_key_id, rotation.to_key_id): rotation for rotation in previous.rotations
    }
    current_rotations = {
        (rotation.from_key_id, rotation.to_key_id): rotation for rotation in current.rotations
    }
    if any(
        current_rotations.get(pair) != rotation for pair, rotation in previous_rotations.items()
    ):
        raise ContractValidationError("existing trust-root rotations cannot change.")
    previous_revocations = {item.key_id: item for item in previous.revocations}
    current_revocations = {item.key_id: item for item in current.revocations}
    for key_id, revocation in previous_revocations.items():
        if current_revocations.get(key_id) != revocation:
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
    expected_digest = f"sha256:{rfc8785_json_sha256_v1(cast(JsonValue, expected_receipt))}"
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


def _resolve_signing_root(
    trust_roots: SangrepPackTrustRootsV1,
    *,
    key_id: str,
    role: SigningRoleV1,
    publisher_id: str,
    channel: PackChannelV1,
    build_profile: BuildProfileV1,
    verification_time: datetime,
) -> PackTrustRootV1:
    root = next((item for item in trust_roots.roots if item.key_id == key_id), None)
    if root is None:
        raise ContractValidationError("signature uses an unknown key.")
    if root.role is not role:
        raise ContractValidationError("trust-root role does not match the signature role.")
    if root.publisher_id != publisher_id:
        raise ContractValidationError("trust-root publisher identity does not match signed bytes.")
    if channel not in root.channels:
        raise ContractValidationError("trust root does not allow the signed channel.")
    if build_profile is BuildProfileV1.RELEASE and (
        channel is PackChannelV1.DEVELOPMENT or PackChannelV1.DEVELOPMENT in root.channels
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


def _require_sha256_value(value: object, *, field_name: str) -> str:
    text = _require_string(value, field_name=field_name)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise ContractValidationError(f"{field_name} must be a lowercase SHA-256 value.")
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
