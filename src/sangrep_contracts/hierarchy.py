"""Canonical evidence hierarchy and projection-node contracts for wire schema v1."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import ClassVar, Self, cast

from .canonical import (
    ContractValidationError,
    FrozenJsonObjectV1,
    FrozenJsonValueV1,
    JsonObjectValue,
    JsonValue,
    canonical_json_sha256,
    canonical_json_sha256_omitting_field_v1,
    freeze_json_object_v1,
    freeze_json_value_v1,
    require_sha256,
    thaw_json_object_v1,
    thaw_json_value_v1,
)
from .citation import (
    FilesystemInventoryEntryLocatorV1,
    MediaRegionLocatorV1,
    PageRegionLocatorV1,
    SectionLocatorV1,
    SourceLocatorV1,
    TableRangeLocatorV1,
    TextFileLocatorV1,
    source_locator_from_json_obj,
)
from .identity import (
    EvidenceCoverageStateV1,
    _parse_code_list,
    _require_code_tuple,
    _require_enum,
    _require_exact_wire_fields,
    _require_identifier,
    _require_json_object,
    _require_kind,
    _require_non_negative_int,
    _require_optional_identifier,
    _require_schema_version,
    _require_string,
    _validate_canonical_wire,
)


class ContainmentKindV1(str, Enum):
    PHYSICAL = "physical"
    SEMANTIC = "semantic"
    EMBEDDED = "embedded"
    REFERENCE = "reference"
    DERIVED_OVERLAY = "derivedOverlay"


class EvidenceNodeKindV1(str, Enum):
    ROOT = "root"
    DOCUMENT = "document"
    SECTION = "section"
    HEADING = "heading"
    PARAGRAPH = "paragraph"
    LIST = "list"
    LIST_ITEM = "listItem"
    TABLE = "table"
    TABLE_ROW = "tableRow"
    TABLE_CELL = "tableCell"
    PAGE = "page"
    MEDIA = "media"
    CODE_BLOCK = "codeBlock"
    BLOCKQUOTE = "blockquote"
    OMISSION = "omission"
    UNKNOWN = "unknown"


class ProjectionPayloadKindV1(str, Enum):
    TEXT = "text"
    MARKDOWN = "markdown"
    HTML = "html"
    JSON_BLOCKS = "jsonBlocks"
    THUMBNAIL = "thumbnail"
    MEDIA_ENVELOPE = "mediaEnvelope"
    EMPTY = "empty"


class ProjectionInclusionStateV1(str, Enum):
    INCLUDED = "included"
    EXCLUDED = "excluded"
    SUMMARIZED = "summarized"
    REDACTED = "redacted"
    OMITTED = "omitted"


class CitableStateV1(str, Enum):
    CITABLE = "citable"
    NOT_CITABLE = "notCitable"
    LIMITED = "limited"


@dataclass(frozen=True, slots=True)
class EvidenceNodeV1:
    evidence_version_id: str
    structure_revision_id: str
    root_anchor_id: str
    anchor_id: str
    occurrence_id: str
    parent_anchor_id: str | None
    parent_occurrence_id: str | None
    containment_kind: ContainmentKindV1
    ordinal: int
    node_kind: EvidenceNodeKindV1
    title: str | None
    structural_content: FrozenJsonObjectV1
    source_locator: SourceLocatorV1
    coverage_state: EvidenceCoverageStateV1
    canonical_node_sha256: str
    warning_codes: tuple[str, ...] = ()
    omission_codes: tuple[str, ...] = ()

    _WIRE_KIND: ClassVar[str] = "evidenceNode"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "schemaVersion",
            "kind",
            "evidenceVersionId",
            "structureRevisionId",
            "rootAnchorId",
            "anchorId",
            "occurrenceId",
            "parentAnchorId",
            "parentOccurrenceId",
            "containmentKind",
            "ordinal",
            "nodeKind",
            "title",
            "structuralContent",
            "sourceLocator",
            "coverageState",
            "warningCodes",
            "omissionCodes",
            "canonicalNodeSha256",
        }
    )

    def __post_init__(self) -> None:
        _require_identifier(self.evidence_version_id, field_name="evidence_version_id")
        _require_identifier(self.structure_revision_id, field_name="structure_revision_id")
        _require_identifier(self.root_anchor_id, field_name="root_anchor_id")
        _require_identifier(self.anchor_id, field_name="anchor_id")
        _require_identifier(self.occurrence_id, field_name="occurrence_id")
        _require_optional_identifier(self.parent_anchor_id, field_name="parent_anchor_id")
        _require_optional_identifier(self.parent_occurrence_id, field_name="parent_occurrence_id")
        if (self.parent_anchor_id is None) != (self.parent_occurrence_id is None):
            raise ContractValidationError(
                "parent anchor and occurrence identifiers must be paired."
            )
        if self.anchor_id == self.root_anchor_id:
            if self.parent_anchor_id is not None:
                raise ContractValidationError("root evidence node must not have a parent.")
        elif self.parent_anchor_id is None:
            raise ContractValidationError("non-root evidence node must have a parent.")
        if not isinstance(self.containment_kind, ContainmentKindV1):
            raise ContractValidationError("containment_kind contains an unknown enum value.")
        _require_non_negative_int(self.ordinal, field_name="ordinal")
        if not isinstance(self.node_kind, EvidenceNodeKindV1):
            raise ContractValidationError("node_kind contains an unknown enum value.")
        if self.title is not None and type(self.title) is not str:
            raise ContractValidationError("title must be a string or null.")
        if not isinstance(self.structural_content, FrozenJsonObjectV1):
            raise ContractValidationError("structural_content must be a frozen JSON object.")
        if type(self.source_locator) not in (
            FilesystemInventoryEntryLocatorV1,
            TextFileLocatorV1,
            SectionLocatorV1,
            TableRangeLocatorV1,
            PageRegionLocatorV1,
            MediaRegionLocatorV1,
        ):
            raise ContractValidationError("source_locator contains an unknown locator type.")
        if not isinstance(self.coverage_state, EvidenceCoverageStateV1):
            raise ContractValidationError("coverage_state contains an unknown enum value.")
        _require_code_tuple(self.warning_codes, field_name="warning_codes")
        _require_code_tuple(self.omission_codes, field_name="omission_codes")
        if self.coverage_state is EvidenceCoverageStateV1.BLOCKED and not (
            self.warning_codes or self.omission_codes
        ):
            raise ContractValidationError("blocked coverage requires a warning or omission code.")
        if self.node_kind is EvidenceNodeKindV1.OMISSION and not self.omission_codes:
            raise ContractValidationError("omission nodes require an omission code.")
        require_sha256(self.canonical_node_sha256, field_name="canonical_node_sha256")
        wire = self.to_json_obj()
        if self.canonical_node_sha256 != canonical_json_sha256_omitting_field_v1(
            wire, field_name="canonicalNodeSha256"
        ):
            raise ContractValidationError("canonical_node_sha256 does not match the evidence node.")
        _validate_canonical_wire(wire)

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 1,
            "kind": self._WIRE_KIND,
            "evidenceVersionId": self.evidence_version_id,
            "structureRevisionId": self.structure_revision_id,
            "rootAnchorId": self.root_anchor_id,
            "anchorId": self.anchor_id,
            "occurrenceId": self.occurrence_id,
            "parentAnchorId": self.parent_anchor_id,
            "parentOccurrenceId": self.parent_occurrence_id,
            "containmentKind": self.containment_kind.value,
            "ordinal": self.ordinal,
            "nodeKind": self.node_kind.value,
            "title": self.title,
            "structuralContent": thaw_json_object_v1(self.structural_content),
            "sourceLocator": self.source_locator.to_json_obj(),
            "coverageState": self.coverage_state.value,
            "warningCodes": list(self.warning_codes),
            "omissionCodes": list(self.omission_codes),
            "canonicalNodeSha256": self.canonical_node_sha256,
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
                structure_revision_id=_require_identifier(
                    _require_string(
                        payload["structureRevisionId"], field_name="structureRevisionId"
                    ),
                    field_name="structureRevisionId",
                ),
                root_anchor_id=_require_identifier(
                    _require_string(payload["rootAnchorId"], field_name="rootAnchorId"),
                    field_name="rootAnchorId",
                ),
                anchor_id=_require_identifier(
                    _require_string(payload["anchorId"], field_name="anchorId"),
                    field_name="anchorId",
                ),
                occurrence_id=_require_identifier(
                    _require_string(payload["occurrenceId"], field_name="occurrenceId"),
                    field_name="occurrenceId",
                ),
                parent_anchor_id=_require_optional_identifier(
                    payload["parentAnchorId"], field_name="parentAnchorId"
                ),
                parent_occurrence_id=_require_optional_identifier(
                    payload["parentOccurrenceId"], field_name="parentOccurrenceId"
                ),
                containment_kind=_require_enum(
                    ContainmentKindV1, payload["containmentKind"], field_name="containmentKind"
                ),
                ordinal=_require_non_negative_int(payload["ordinal"], field_name="ordinal"),
                node_kind=_require_enum(
                    EvidenceNodeKindV1, payload["nodeKind"], field_name="nodeKind"
                ),
                title=(
                    None
                    if payload["title"] is None
                    else _require_string(payload["title"], field_name="title")
                ),
                structural_content=freeze_json_object_v1(
                    cast(JsonObjectValue, payload["structuralContent"])
                ),
                source_locator=source_locator_from_json_obj(payload["sourceLocator"]),
                coverage_state=_require_enum(
                    EvidenceCoverageStateV1, payload["coverageState"], field_name="coverageState"
                ),
                canonical_node_sha256=require_sha256(
                    _require_string(
                        payload["canonicalNodeSha256"], field_name="canonicalNodeSha256"
                    ),
                    field_name="canonicalNodeSha256",
                ),
                warning_codes=_parse_code_list(payload["warningCodes"], field_name="warningCodes"),
                omission_codes=_parse_code_list(
                    payload["omissionCodes"], field_name="omissionCodes"
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
class ProjectedNodeV1:
    projection_revision_id: str
    structure_revision_id: str
    anchor_id: str
    occurrence_id: str
    payload_kind: ProjectionPayloadKindV1
    payload: FrozenJsonValueV1
    inclusion_state: ProjectionInclusionStateV1
    citable_state: CitableStateV1
    projected_payload_sha256: str
    limitation_codes: tuple[str, ...] = ()

    _WIRE_KIND: ClassVar[str] = "projectedNode"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "schemaVersion",
            "kind",
            "projectionRevisionId",
            "structureRevisionId",
            "anchorId",
            "occurrenceId",
            "payloadKind",
            "payload",
            "inclusionState",
            "citableState",
            "limitationCodes",
            "projectedPayloadSha256",
        }
    )

    def __post_init__(self) -> None:
        _require_identifier(self.projection_revision_id, field_name="projection_revision_id")
        _require_identifier(self.structure_revision_id, field_name="structure_revision_id")
        _require_identifier(self.anchor_id, field_name="anchor_id")
        _require_identifier(self.occurrence_id, field_name="occurrence_id")
        if not isinstance(self.payload_kind, ProjectionPayloadKindV1):
            raise ContractValidationError("payload_kind contains an unknown enum value.")
        payload = thaw_json_value_v1(self.payload)
        if self.payload_kind is ProjectionPayloadKindV1.EMPTY and payload is not None:
            raise ContractValidationError("empty payload kind requires a null payload.")
        if not isinstance(self.inclusion_state, ProjectionInclusionStateV1):
            raise ContractValidationError("inclusion_state contains an unknown enum value.")
        if not isinstance(self.citable_state, CitableStateV1):
            raise ContractValidationError("citable_state contains an unknown enum value.")
        _require_code_tuple(self.limitation_codes, field_name="limitation_codes")
        if (
            self.inclusion_state
            in {
                ProjectionInclusionStateV1.SUMMARIZED,
                ProjectionInclusionStateV1.REDACTED,
                ProjectionInclusionStateV1.OMITTED,
            }
            and not self.limitation_codes
        ):
            raise ContractValidationError("projected inclusion state requires a limitation code.")
        if (
            self.citable_state in {CitableStateV1.NOT_CITABLE, CitableStateV1.LIMITED}
            and not self.limitation_codes
        ):
            raise ContractValidationError("limited citability requires a limitation code.")
        require_sha256(self.projected_payload_sha256, field_name="projected_payload_sha256")
        if self.projected_payload_sha256 != canonical_json_sha256(payload):
            raise ContractValidationError("projected_payload_sha256 does not match the payload.")
        _validate_canonical_wire(self.to_json_obj())

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 1,
            "kind": self._WIRE_KIND,
            "projectionRevisionId": self.projection_revision_id,
            "structureRevisionId": self.structure_revision_id,
            "anchorId": self.anchor_id,
            "occurrenceId": self.occurrence_id,
            "payloadKind": self.payload_kind.value,
            "payload": thaw_json_value_v1(self.payload),
            "inclusionState": self.inclusion_state.value,
            "citableState": self.citable_state.value,
            "limitationCodes": list(self.limitation_codes),
            "projectedPayloadSha256": self.projected_payload_sha256,
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
                        payload["projectionRevisionId"], field_name="projectionRevisionId"
                    ),
                    field_name="projectionRevisionId",
                ),
                structure_revision_id=_require_identifier(
                    _require_string(
                        payload["structureRevisionId"], field_name="structureRevisionId"
                    ),
                    field_name="structureRevisionId",
                ),
                anchor_id=_require_identifier(
                    _require_string(payload["anchorId"], field_name="anchorId"),
                    field_name="anchorId",
                ),
                occurrence_id=_require_identifier(
                    _require_string(payload["occurrenceId"], field_name="occurrenceId"),
                    field_name="occurrenceId",
                ),
                payload_kind=_require_enum(
                    ProjectionPayloadKindV1, payload["payloadKind"], field_name="payloadKind"
                ),
                payload=freeze_json_value_v1(cast(JsonValue, payload["payload"])),
                inclusion_state=_require_enum(
                    ProjectionInclusionStateV1,
                    payload["inclusionState"],
                    field_name="inclusionState",
                ),
                citable_state=_require_enum(
                    CitableStateV1, payload["citableState"], field_name="citableState"
                ),
                projected_payload_sha256=require_sha256(
                    _require_string(
                        payload["projectedPayloadSha256"], field_name="projectedPayloadSha256"
                    ),
                    field_name="projectedPayloadSha256",
                ),
                limitation_codes=_parse_code_list(
                    payload["limitationCodes"], field_name="limitationCodes"
                ),
            )
        except ContractValidationError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError(f"{cls._WIRE_KIND} is malformed.") from None

    @property
    def digest(self) -> str:
        return canonical_json_sha256(self.to_json_obj())
