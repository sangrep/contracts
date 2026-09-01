from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace

import pytest

from sangrep_contracts import (
    CitableStateV1,
    ContainmentKindV1,
    ContractValidationError,
    EvidenceCoverageStateV1,
    EvidenceNodeKindV1,
    EvidenceNodeV1,
    FilesystemInventoryEntryLocatorV1,
    MediaRegionLocatorV1,
    PageRegionLocatorV1,
    ProjectedNodeV1,
    ProjectionInclusionStateV1,
    ProjectionPayloadKindV1,
    SectionLocatorV1,
    SourceLocatorV1,
    TableRangeLocatorV1,
    TextFileLocatorV1,
    canonical_json_sha256,
    canonical_json_sha256_omitting_field_v1,
    freeze_json_object_v1,
    freeze_json_value_v1,
)


def _node_sha256(wire: dict[str, object]) -> str:
    return canonical_json_sha256_omitting_field_v1(wire, field_name="canonicalNodeSha256")


def _section_node() -> EvidenceNodeV1:
    structural_content = freeze_json_object_v1({"text": "Scope"})
    source_locator = SectionLocatorV1("source:policy:v1", (0,))
    canonical_node_sha256 = _node_sha256(
        {
            "schemaVersion": 1,
            "kind": "evidenceNode",
            "evidenceVersionId": "evidence:v1",
            "structureRevisionId": "structure:v1",
            "rootAnchorId": "anchor:root",
            "anchorId": "anchor:section:1",
            "occurrenceId": "occurrence:section:1",
            "parentAnchorId": "anchor:root",
            "parentOccurrenceId": "occurrence:root",
            "containmentKind": "semantic",
            "ordinal": 0,
            "nodeKind": "section",
            "title": "Scope",
            "structuralContent": {"text": "Scope"},
            "sourceLocator": source_locator.to_json_obj(),
            "coverageState": "complete",
            "warningCodes": [],
            "omissionCodes": [],
            "canonicalNodeSha256": "0" * 64,
        }
    )
    return EvidenceNodeV1(
        evidence_version_id="evidence:v1",
        structure_revision_id="structure:v1",
        root_anchor_id="anchor:root",
        anchor_id="anchor:section:1",
        occurrence_id="occurrence:section:1",
        parent_anchor_id="anchor:root",
        parent_occurrence_id="occurrence:root",
        containment_kind=ContainmentKindV1.SEMANTIC,
        ordinal=0,
        node_kind=EvidenceNodeKindV1.SECTION,
        title="Scope",
        structural_content=structural_content,
        source_locator=source_locator,
        coverage_state=EvidenceCoverageStateV1.COMPLETE,
        canonical_node_sha256=canonical_node_sha256,
    )


def _table_node() -> EvidenceNodeV1:
    structural_content = freeze_json_object_v1({"columns": ["Control", "Owner"]})
    source_locator = TableRangeLocatorV1("source:policy:v1", (0,), 1, 3, 1, 2)
    canonical_node_sha256 = _node_sha256(
        {
            "schemaVersion": 1,
            "kind": "evidenceNode",
            "evidenceVersionId": "evidence:v1",
            "structureRevisionId": "structure:v1",
            "rootAnchorId": "anchor:root",
            "anchorId": "anchor:table:1",
            "occurrenceId": "occurrence:table:1",
            "parentAnchorId": "anchor:section:1",
            "parentOccurrenceId": "occurrence:section:1",
            "containmentKind": "semantic",
            "ordinal": 1,
            "nodeKind": "table",
            "title": "Control Matrix",
            "structuralContent": {"columns": ["Control", "Owner"]},
            "sourceLocator": source_locator.to_json_obj(),
            "coverageState": "complete",
            "warningCodes": [],
            "omissionCodes": [],
            "canonicalNodeSha256": "0" * 64,
        }
    )
    return EvidenceNodeV1(
        evidence_version_id="evidence:v1",
        structure_revision_id="structure:v1",
        root_anchor_id="anchor:root",
        anchor_id="anchor:table:1",
        occurrence_id="occurrence:table:1",
        parent_anchor_id="anchor:section:1",
        parent_occurrence_id="occurrence:section:1",
        containment_kind=ContainmentKindV1.SEMANTIC,
        ordinal=1,
        node_kind=EvidenceNodeKindV1.TABLE,
        title="Control Matrix",
        structural_content=structural_content,
        source_locator=source_locator,
        coverage_state=EvidenceCoverageStateV1.COMPLETE,
        canonical_node_sha256=canonical_node_sha256,
    )


def _node_with_locator(source_locator: SourceLocatorV1) -> EvidenceNodeV1:
    node = _section_node()
    wire = node.to_json_obj()
    wire["sourceLocator"] = source_locator.to_json_obj()
    wire["canonicalNodeSha256"] = _node_sha256(wire)
    return replace(
        node,
        source_locator=source_locator,
        canonical_node_sha256=wire["canonicalNodeSha256"],
    )


def _projected_section() -> ProjectedNodeV1:
    return ProjectedNodeV1(
        projection_revision_id="projection:reviewer:v1",
        structure_revision_id="structure:v1",
        anchor_id="anchor:section:1",
        occurrence_id="occurrence:section:1",
        payload_kind=ProjectionPayloadKindV1.MARKDOWN,
        payload=freeze_json_value_v1({"text": "## Scope"}),
        inclusion_state=ProjectionInclusionStateV1.INCLUDED,
        citable_state=CitableStateV1.CITABLE,
        projected_payload_sha256=canonical_json_sha256({"text": "## Scope"}),
    )


def test_evidence_node_round_trips_exact_wire_and_keeps_occurrence_identity() -> None:
    node = _section_node()

    assert node.to_json_obj() == {
        "schemaVersion": 1,
        "kind": "evidenceNode",
        "evidenceVersionId": "evidence:v1",
        "structureRevisionId": "structure:v1",
        "rootAnchorId": "anchor:root",
        "anchorId": "anchor:section:1",
        "occurrenceId": "occurrence:section:1",
        "parentAnchorId": "anchor:root",
        "parentOccurrenceId": "occurrence:root",
        "containmentKind": "semantic",
        "ordinal": 0,
        "nodeKind": "section",
        "title": "Scope",
        "structuralContent": {"text": "Scope"},
        "sourceLocator": {
            "kind": "section",
            "sourceVersionId": "source:policy:v1",
            "sectionOrdinalPath": [0],
        },
        "coverageState": "complete",
        "warningCodes": [],
        "omissionCodes": [],
        "canonicalNodeSha256": node.canonical_node_sha256,
    }
    assert EvidenceNodeV1.from_json_obj(node.to_json_obj()) == node
    assert len(node.digest) == 64


def test_projected_node_round_trips_and_payload_digest_matches_payload() -> None:
    projected = _projected_section()

    assert ProjectedNodeV1.from_json_obj(projected.to_json_obj()) == projected
    assert projected.projected_payload_sha256 == canonical_json_sha256({"text": "## Scope"})
    assert projected.to_json_obj()["payload"] == {"text": "## Scope"}


@pytest.mark.parametrize(
    "source_locator",
    [
        FilesystemInventoryEntryLocatorV1("snapshot:v1", "entry:policy"),
        TextFileLocatorV1("source:policy:v1", "policy.md", 1, 3, 0, 30),
        SectionLocatorV1("source:policy:v1", (0,)),
        TableRangeLocatorV1("source:policy:v1", (0,), 1, 3, 1, 2),
        PageRegionLocatorV1("source:policy:v1", 1, 0, 0, 100, 100, "page-unit-10000"),
        MediaRegionLocatorV1(
            "source:policy:v1",
            "media:chart:1",
            0,
            0,
            100,
            100,
            "media-unit-10000",
        ),
    ],
)
def test_evidence_node_rejects_source_locator_subclasses_before_serialization(
    source_locator: SourceLocatorV1,
) -> None:
    exact_node = _node_with_locator(source_locator)
    assert EvidenceNodeV1.from_json_obj(exact_node.to_json_obj()) == exact_node
    locator_type = type(source_locator)
    locator_subclass = type(f"Adversarial{locator_type.__name__}", (locator_type,), {})
    subclass_value = locator_subclass(
        **{field.name: getattr(source_locator, field.name) for field in fields(source_locator)}
    )

    def fail_if_serialized(_value: object) -> object:
        raise AssertionError("source locator subclass was serialized")

    locator_subclass.to_json_obj = fail_if_serialized

    with pytest.raises(ContractValidationError, match="source_locator"):
        replace(exact_node, source_locator=subclass_value)


def test_from_json_freezes_json_bearing_fields_and_to_json_thaws_fresh_payloads() -> None:
    wire = _section_node().to_json_obj()
    wire["structuralContent"] = {"text": "Scope", "children": [{"kind": "paragraph"}]}
    wire["canonicalNodeSha256"] = _node_sha256(wire)
    node = EvidenceNodeV1.from_json_obj(wire)
    wire["structuralContent"]["children"][0]["kind"] = "mutated"  # type: ignore[index]

    assert node.to_json_obj()["structuralContent"] == {
        "children": [{"kind": "paragraph"}],
        "text": "Scope",
    }

    first = node.to_json_obj()
    second = node.to_json_obj()
    first["structuralContent"]["children"][0]["kind"] = "changed"  # type: ignore[index]
    assert second["structuralContent"] == {"children": [{"kind": "paragraph"}], "text": "Scope"}


def test_hierarchy_and_projection_types_are_frozen_and_slotted() -> None:
    node = _section_node()
    projected = _projected_section()

    assert not hasattr(node, "__dict__")
    assert not hasattr(projected, "__dict__")
    with pytest.raises(FrozenInstanceError):
        node.ordinal = 9  # type: ignore[misc]


@pytest.mark.parametrize(
    "change",
    [
        {"occurrence_id": ""},
        {"parent_anchor_id": None, "parent_occurrence_id": "occurrence:root"},
        {"parent_anchor_id": "anchor:root", "parent_occurrence_id": None},
        {
            "coverage_state": EvidenceCoverageStateV1.BLOCKED,
            "warning_codes": (),
            "omission_codes": (),
        },
        {"node_kind": EvidenceNodeKindV1.OMISSION, "omission_codes": ()},
        {"canonical_node_sha256": "0" * 64},
    ],
)
def test_evidence_node_rejects_identity_parent_state_and_digest_contradictions(
    change: dict[str, object],
) -> None:
    with pytest.raises(ContractValidationError):
        replace(_section_node(), **change)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "change",
    [
        {
            "payload_kind": ProjectionPayloadKindV1.EMPTY,
            "payload": freeze_json_value_v1({"not": "empty"}),
        },
        {"inclusion_state": ProjectionInclusionStateV1.REDACTED, "limitation_codes": ()},
        {"inclusion_state": ProjectionInclusionStateV1.OMITTED, "limitation_codes": ()},
        {"citable_state": CitableStateV1.NOT_CITABLE, "limitation_codes": ()},
        {"projected_payload_sha256": "0" * 64},
    ],
)
def test_projected_node_rejects_payload_inclusion_citable_and_digest_contradictions(
    change: dict[str, object],
) -> None:
    with pytest.raises(ContractValidationError):
        replace(_projected_section(), **change)  # type: ignore[arg-type]
