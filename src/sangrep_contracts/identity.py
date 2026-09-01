"""Immutable source-to-projection identity contracts for wire schema v1."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import ClassVar, Self, TypeVar

from .canonical import (
    MAX_SAFE_INTEGER,
    ContractValidationError,
    JsonValue,
    canonical_json_bytes,
    canonical_json_sha256,
    require_sha256,
)

IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
CODE = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
MEDIA_TYPE = re.compile(r"[a-z0-9!#$&^_.+-]+/[a-z0-9!#$&^_.+-]+\Z")
EnumType = TypeVar("EnumType", bound=Enum)


class SourceObjectKindV1(str, Enum):
    FILE = "file"
    BLOB = "blob"
    PACKAGE_PART = "packagePart"
    EMBEDDED_OCCURRENCE = "embeddedOccurrence"
    PAGE_IMAGE = "pageImage"
    OTHER = "other"


class CustodyStateV1(str, Enum):
    EXTERNAL_READ_ONLY = "externalReadOnly"
    RETAINED_COPY = "retainedCopy"
    EPHEMERAL = "ephemeral"
    UNAVAILABLE = "unavailable"


class EvidenceCoverageStateV1(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    BLOCKED = "blocked"


def _require_identifier(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise ContractValidationError(f"{field_name} is not a valid v1 identifier.")
    return value


def _require_unique_codes(values: tuple[str, ...], *, field_name: str) -> tuple[str, ...]:
    if len(values) != len(set(values)):
        raise ContractValidationError(f"{field_name} contains a duplicate code.")
    if any(CODE.fullmatch(value) is None for value in values):
        raise ContractValidationError(f"{field_name} contains an invalid code.")
    return values


def _require_json_object(value: object, *, field_name: str) -> dict[str, object]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ContractValidationError(f"{field_name} must be a JSON object.")
    return value


def _require_exact_wire_fields(
    payload: dict[str, object],
    *,
    expected_keys: frozenset[str],
    field_name: str,
) -> dict[str, object]:
    if frozenset(payload) != expected_keys:
        raise ContractValidationError(f"{field_name} has missing or unknown fields.")
    return payload


def _require_schema_version(value: object) -> None:
    if type(value) is not int or value != 1:
        raise ContractValidationError("schemaVersion must equal 1.")


def _require_kind(value: object, *, expected_kind: str) -> None:
    if type(value) is not str or value != expected_kind:
        raise ContractValidationError(f"kind must equal {expected_kind}.")


def _require_non_negative_int(value: object, *, field_name: str) -> int:
    if type(value) is not int or value < 0 or value > MAX_SAFE_INTEGER:
        raise ContractValidationError(f"{field_name} must be a safe non-negative integer.")
    return value


def _require_media_type(value: object, *, field_name: str) -> str:
    if type(value) is not str or MEDIA_TYPE.fullmatch(value) is None:
        raise ContractValidationError(f"{field_name} is not a valid lowercase media type.")
    return value


def _require_string(value: object, *, field_name: str) -> str:
    if type(value) is not str:
        raise ContractValidationError(f"{field_name} must be a string.")
    return value


def _require_optional_identifier(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    return _require_identifier(_require_string(value, field_name=field_name), field_name=field_name)


def _require_enum(
    enum_type: type[EnumType],
    value: object,
    *,
    field_name: str,
) -> EnumType:
    if type(value) is not str:
        raise ContractValidationError(f"{field_name} must be a string enum value.")
    try:
        return enum_type(value)
    except ValueError:
        raise ContractValidationError(f"{field_name} contains an unknown enum value.") from None


def _require_identifier_tuple(
    values: object,
    *,
    field_name: str,
    allow_empty: bool,
) -> tuple[str, ...]:
    if type(values) is not tuple:
        raise ContractValidationError(f"{field_name} must be a tuple of identifiers.")
    result = tuple(_require_identifier(value, field_name=field_name) for value in values)
    if not allow_empty and not result:
        raise ContractValidationError(f"{field_name} must not be empty.")
    if len(result) != len(set(result)):
        raise ContractValidationError(f"{field_name} contains a duplicate identifier.")
    return result


def _require_code_tuple(values: object, *, field_name: str) -> tuple[str, ...]:
    if type(values) is not tuple:
        raise ContractValidationError(f"{field_name} must be a tuple of codes.")
    if any(type(value) is not str for value in values):
        raise ContractValidationError(f"{field_name} must be a tuple of codes.")
    return _require_unique_codes(values, field_name=field_name)


def _require_provenance(value: object, *, field_name: str) -> tuple[tuple[str, str], ...]:
    if type(value) is not tuple:
        raise ContractValidationError(f"{field_name} must be a tuple of string pairs.")
    result: list[tuple[str, str]] = []
    seen_keys: set[str] = set()
    for entry in value:
        if type(entry) is not tuple or len(entry) != 2:
            raise ContractValidationError(f"{field_name} must contain key/value string pairs.")
        key, item_value = entry
        if type(key) is not str or type(item_value) is not str:
            raise ContractValidationError(f"{field_name} must contain key/value string pairs.")
        if key in seen_keys:
            raise ContractValidationError(f"{field_name} contains a duplicate provenance key.")
        seen_keys.add(key)
        result.append((key, item_value))
    return tuple(result)


def _parse_identifier_list(
    values: object,
    *,
    field_name: str,
    allow_empty: bool,
) -> tuple[str, ...]:
    if type(values) is not list:
        raise ContractValidationError(f"{field_name} must be a JSON array.")
    return _require_identifier_tuple(tuple(values), field_name=field_name, allow_empty=allow_empty)


def _parse_code_list(values: object, *, field_name: str) -> tuple[str, ...]:
    if type(values) is not list:
        raise ContractValidationError(f"{field_name} must be a JSON array.")
    return _require_code_tuple(tuple(values), field_name=field_name)


def _parse_provenance_object(value: object, *, field_name: str) -> tuple[tuple[str, str], ...]:
    payload = _require_json_object(value, field_name=field_name)
    for item_value in payload.values():
        if type(item_value) is not str:
            raise ContractValidationError(f"{field_name} must be a string object.")
    return _require_provenance(tuple((key, payload[key]) for key in payload), field_name=field_name)


def _validate_canonical_wire(payload: dict[str, JsonValue]) -> None:
    canonical_json_bytes(payload)


@dataclass(frozen=True, slots=True)
class SourceObjectVersionV1:
    source_object_id: str
    source_version_id: str
    object_kind: SourceObjectKindV1
    byte_size: int
    content_sha256: str
    media_type: str
    custody_state: CustodyStateV1
    provenance: tuple[tuple[str, str], ...] = ()

    _WIRE_KIND: ClassVar[str] = "sourceObjectVersion"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "schemaVersion",
            "kind",
            "sourceObjectId",
            "sourceVersionId",
            "objectKind",
            "byteSize",
            "contentSha256",
            "mediaType",
            "custodyState",
            "provenance",
        }
    )

    def __post_init__(self) -> None:
        _require_identifier(self.source_object_id, field_name="source_object_id")
        _require_identifier(self.source_version_id, field_name="source_version_id")
        if not isinstance(self.object_kind, SourceObjectKindV1):
            raise ContractValidationError("object_kind contains an unknown enum value.")
        _require_non_negative_int(self.byte_size, field_name="byte_size")
        require_sha256(self.content_sha256, field_name="content_sha256")
        _require_media_type(self.media_type, field_name="media_type")
        if not isinstance(self.custody_state, CustodyStateV1):
            raise ContractValidationError("custody_state contains an unknown enum value.")
        _require_provenance(self.provenance, field_name="provenance")
        _validate_canonical_wire(self.to_json_obj())

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 1,
            "kind": self._WIRE_KIND,
            "sourceObjectId": self.source_object_id,
            "sourceVersionId": self.source_version_id,
            "objectKind": self.object_kind.value,
            "byteSize": self.byte_size,
            "contentSha256": self.content_sha256,
            "mediaType": self.media_type,
            "custodyState": self.custody_state.value,
            "provenance": {key: value for key, value in self.provenance},
        }

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        try:
            payload = _require_exact_wire_fields(
                _require_json_object(value, field_name=cls._WIRE_KIND),
                expected_keys=cls._WIRE_KEYS,
                field_name=cls._WIRE_KIND,
            )
            _require_schema_version(payload["schemaVersion"])
            _require_kind(payload["kind"], expected_kind=cls._WIRE_KIND)
            return cls(
                source_object_id=_require_identifier(
                    _require_string(payload["sourceObjectId"], field_name="sourceObjectId"),
                    field_name="sourceObjectId",
                ),
                source_version_id=_require_identifier(
                    _require_string(payload["sourceVersionId"], field_name="sourceVersionId"),
                    field_name="sourceVersionId",
                ),
                object_kind=_require_enum(
                    SourceObjectKindV1,
                    payload["objectKind"],
                    field_name="objectKind",
                ),
                byte_size=_require_non_negative_int(payload["byteSize"], field_name="byteSize"),
                content_sha256=require_sha256(
                    _require_string(payload["contentSha256"], field_name="contentSha256"),
                    field_name="contentSha256",
                ),
                media_type=_require_media_type(payload["mediaType"], field_name="mediaType"),
                custody_state=_require_enum(
                    CustodyStateV1,
                    payload["custodyState"],
                    field_name="custodyState",
                ),
                provenance=_parse_provenance_object(payload["provenance"], field_name="provenance"),
            )
        except ContractValidationError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError(f"{cls._WIRE_KIND} is malformed.") from None

    @property
    def digest(self) -> str:
        return canonical_json_sha256(self.to_json_obj())


@dataclass(frozen=True, slots=True)
class EvidenceVersionV1:
    evidence_version_id: str
    source_version_ids: tuple[str, ...]
    adapter_profile_id: str
    adapter_profile_sha256: str
    coverage_state: EvidenceCoverageStateV1
    warning_codes: tuple[str, ...]
    blocker_codes: tuple[str, ...]
    canonical_output_sha256: str

    _WIRE_KIND: ClassVar[str] = "evidenceVersion"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "schemaVersion",
            "kind",
            "evidenceVersionId",
            "sourceVersionIds",
            "adapterProfileId",
            "adapterProfileSha256",
            "coverageState",
            "warningCodes",
            "blockerCodes",
            "canonicalOutputSha256",
        }
    )

    def __post_init__(self) -> None:
        _require_identifier(self.evidence_version_id, field_name="evidence_version_id")
        _require_identifier_tuple(
            self.source_version_ids,
            field_name="source_version_ids",
            allow_empty=False,
        )
        _require_identifier(self.adapter_profile_id, field_name="adapter_profile_id")
        require_sha256(self.adapter_profile_sha256, field_name="adapter_profile_sha256")
        if not isinstance(self.coverage_state, EvidenceCoverageStateV1):
            raise ContractValidationError("coverage_state contains an unknown enum value.")
        _require_code_tuple(self.warning_codes, field_name="warning_codes")
        _require_code_tuple(self.blocker_codes, field_name="blocker_codes")
        require_sha256(self.canonical_output_sha256, field_name="canonical_output_sha256")
        _validate_canonical_wire(self.to_json_obj())

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 1,
            "kind": self._WIRE_KIND,
            "evidenceVersionId": self.evidence_version_id,
            "sourceVersionIds": list(self.source_version_ids),
            "adapterProfileId": self.adapter_profile_id,
            "adapterProfileSha256": self.adapter_profile_sha256,
            "coverageState": self.coverage_state.value,
            "warningCodes": list(self.warning_codes),
            "blockerCodes": list(self.blocker_codes),
            "canonicalOutputSha256": self.canonical_output_sha256,
        }

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        try:
            payload = _require_exact_wire_fields(
                _require_json_object(value, field_name=cls._WIRE_KIND),
                expected_keys=cls._WIRE_KEYS,
                field_name=cls._WIRE_KIND,
            )
            _require_schema_version(payload["schemaVersion"])
            _require_kind(payload["kind"], expected_kind=cls._WIRE_KIND)
            return cls(
                evidence_version_id=_require_identifier(
                    _require_string(payload["evidenceVersionId"], field_name="evidenceVersionId"),
                    field_name="evidenceVersionId",
                ),
                source_version_ids=_parse_identifier_list(
                    payload["sourceVersionIds"],
                    field_name="sourceVersionIds",
                    allow_empty=False,
                ),
                adapter_profile_id=_require_identifier(
                    _require_string(payload["adapterProfileId"], field_name="adapterProfileId"),
                    field_name="adapterProfileId",
                ),
                adapter_profile_sha256=require_sha256(
                    _require_string(
                        payload["adapterProfileSha256"],
                        field_name="adapterProfileSha256",
                    ),
                    field_name="adapterProfileSha256",
                ),
                coverage_state=_require_enum(
                    EvidenceCoverageStateV1,
                    payload["coverageState"],
                    field_name="coverageState",
                ),
                warning_codes=_parse_code_list(payload["warningCodes"], field_name="warningCodes"),
                blocker_codes=_parse_code_list(payload["blockerCodes"], field_name="blockerCodes"),
                canonical_output_sha256=require_sha256(
                    _require_string(
                        payload["canonicalOutputSha256"],
                        field_name="canonicalOutputSha256",
                    ),
                    field_name="canonicalOutputSha256",
                ),
            )
        except ContractValidationError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError(f"{cls._WIRE_KIND} is malformed.") from None

    @property
    def digest(self) -> str:
        return canonical_json_sha256(self.to_json_obj())


@dataclass(frozen=True, slots=True)
class StructureRevisionV1:
    structure_revision_id: str
    evidence_version_id: str
    structure_profile_id: str
    structure_profile_sha256: str
    graph_sha256: str

    _WIRE_KIND: ClassVar[str] = "structureRevision"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "schemaVersion",
            "kind",
            "structureRevisionId",
            "evidenceVersionId",
            "structureProfileId",
            "structureProfileSha256",
            "graphSha256",
        }
    )

    def __post_init__(self) -> None:
        _require_identifier(self.structure_revision_id, field_name="structure_revision_id")
        _require_identifier(self.evidence_version_id, field_name="evidence_version_id")
        _require_identifier(self.structure_profile_id, field_name="structure_profile_id")
        require_sha256(self.structure_profile_sha256, field_name="structure_profile_sha256")
        require_sha256(self.graph_sha256, field_name="graph_sha256")
        _validate_canonical_wire(self.to_json_obj())

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 1,
            "kind": self._WIRE_KIND,
            "structureRevisionId": self.structure_revision_id,
            "evidenceVersionId": self.evidence_version_id,
            "structureProfileId": self.structure_profile_id,
            "structureProfileSha256": self.structure_profile_sha256,
            "graphSha256": self.graph_sha256,
        }

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        try:
            payload = _require_exact_wire_fields(
                _require_json_object(value, field_name=cls._WIRE_KIND),
                expected_keys=cls._WIRE_KEYS,
                field_name=cls._WIRE_KIND,
            )
            _require_schema_version(payload["schemaVersion"])
            _require_kind(payload["kind"], expected_kind=cls._WIRE_KIND)
            return cls(
                structure_revision_id=_require_identifier(
                    _require_string(
                        payload["structureRevisionId"],
                        field_name="structureRevisionId",
                    ),
                    field_name="structureRevisionId",
                ),
                evidence_version_id=_require_identifier(
                    _require_string(
                        payload["evidenceVersionId"],
                        field_name="evidenceVersionId",
                    ),
                    field_name="evidenceVersionId",
                ),
                structure_profile_id=_require_identifier(
                    _require_string(
                        payload["structureProfileId"],
                        field_name="structureProfileId",
                    ),
                    field_name="structureProfileId",
                ),
                structure_profile_sha256=require_sha256(
                    _require_string(
                        payload["structureProfileSha256"],
                        field_name="structureProfileSha256",
                    ),
                    field_name="structureProfileSha256",
                ),
                graph_sha256=require_sha256(
                    _require_string(payload["graphSha256"], field_name="graphSha256"),
                    field_name="graphSha256",
                ),
            )
        except ContractValidationError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError(f"{cls._WIRE_KIND} is malformed.") from None

    @property
    def digest(self) -> str:
        return canonical_json_sha256(self.to_json_obj())


@dataclass(frozen=True, slots=True)
class ProjectionRevisionV1:
    projection_revision_id: str
    structure_revision_id: str
    projection_profile_id: str
    projection_profile_version: str
    projection_profile_sha256: str
    payload_sha256: str

    _WIRE_KIND: ClassVar[str] = "projectionRevision"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "schemaVersion",
            "kind",
            "projectionRevisionId",
            "structureRevisionId",
            "projectionProfileId",
            "projectionProfileVersion",
            "projectionProfileSha256",
            "payloadSha256",
        }
    )

    def __post_init__(self) -> None:
        _require_identifier(self.projection_revision_id, field_name="projection_revision_id")
        _require_identifier(self.structure_revision_id, field_name="structure_revision_id")
        _require_identifier(self.projection_profile_id, field_name="projection_profile_id")
        _require_identifier(
            self.projection_profile_version,
            field_name="projection_profile_version",
        )
        require_sha256(self.projection_profile_sha256, field_name="projection_profile_sha256")
        require_sha256(self.payload_sha256, field_name="payload_sha256")
        _validate_canonical_wire(self.to_json_obj())

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 1,
            "kind": self._WIRE_KIND,
            "projectionRevisionId": self.projection_revision_id,
            "structureRevisionId": self.structure_revision_id,
            "projectionProfileId": self.projection_profile_id,
            "projectionProfileVersion": self.projection_profile_version,
            "projectionProfileSha256": self.projection_profile_sha256,
            "payloadSha256": self.payload_sha256,
        }

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        try:
            payload = _require_exact_wire_fields(
                _require_json_object(value, field_name=cls._WIRE_KIND),
                expected_keys=cls._WIRE_KEYS,
                field_name=cls._WIRE_KIND,
            )
            _require_schema_version(payload["schemaVersion"])
            _require_kind(payload["kind"], expected_kind=cls._WIRE_KIND)
            return cls(
                projection_revision_id=_require_identifier(
                    _require_string(
                        payload["projectionRevisionId"],
                        field_name="projectionRevisionId",
                    ),
                    field_name="projectionRevisionId",
                ),
                structure_revision_id=_require_identifier(
                    _require_string(
                        payload["structureRevisionId"],
                        field_name="structureRevisionId",
                    ),
                    field_name="structureRevisionId",
                ),
                projection_profile_id=_require_identifier(
                    _require_string(
                        payload["projectionProfileId"],
                        field_name="projectionProfileId",
                    ),
                    field_name="projectionProfileId",
                ),
                projection_profile_version=_require_identifier(
                    _require_string(
                        payload["projectionProfileVersion"],
                        field_name="projectionProfileVersion",
                    ),
                    field_name="projectionProfileVersion",
                ),
                projection_profile_sha256=require_sha256(
                    _require_string(
                        payload["projectionProfileSha256"],
                        field_name="projectionProfileSha256",
                    ),
                    field_name="projectionProfileSha256",
                ),
                payload_sha256=require_sha256(
                    _require_string(payload["payloadSha256"], field_name="payloadSha256"),
                    field_name="payloadSha256",
                ),
            )
        except ContractValidationError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError(f"{cls._WIRE_KIND} is malformed.") from None

    @property
    def digest(self) -> str:
        return canonical_json_sha256(self.to_json_obj())
