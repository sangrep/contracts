from __future__ import annotations

from dataclasses import FrozenInstanceError, fields, replace

import pytest

from sangrep_contracts import (
    CitationAddressV1,
    ContractValidationError,
    LineRangeSelectorV1,
    MediaRegionSelectorV1,
    NodeSelectorV1,
    PageRegionSelectorV1,
    SectionSelectorV1,
    TableRangeSelectorV1,
    TextSpanSelectorV1,
)


def _node_selector() -> NodeSelectorV1:
    return NodeSelectorV1(anchor_id="anchor:limitation")


def _line_selector() -> LineRangeSelectorV1:
    return LineRangeSelectorV1(start_line=88, end_line=103)


def _text_selector() -> TextSpanSelectorV1:
    return TextSpanSelectorV1(start_offset=120, end_offset=188)


def _section_selector() -> SectionSelectorV1:
    return SectionSelectorV1(section_ordinal_path=(0, 2))


def _table_selector() -> TableRangeSelectorV1:
    return TableRangeSelectorV1(
        table_ordinal_path=(1,), start_row=1, end_row=3, start_column=1, end_column=2
    )


def _page_selector() -> PageRegionSelectorV1:
    return PageRegionSelectorV1(
        page_number=2,
        x=100,
        y=200,
        width=900,
        height=400,
        coordinate_profile="page-unit-10000",
    )


def _media_selector() -> MediaRegionSelectorV1:
    return MediaRegionSelectorV1(
        media_object_id="media:chart:1",
        x=50,
        y=75,
        width=600,
        height=300,
        coordinate_profile="media-unit-10000",
    )


def test_issue_30_text_selectors_keep_original_closed_wire_shapes() -> None:
    assert NodeSelectorV1(anchor_id="anchor:body").to_json_obj() == {
        "kind": "node",
        "anchorId": "anchor:body",
    }
    assert LineRangeSelectorV1(start_line=2, end_line=5).to_json_obj() == {
        "kind": "lineRange",
        "startLine": 2,
        "endLine": 5,
    }
    assert TextSpanSelectorV1(start_offset=10, end_offset=14).to_json_obj() == {
        "kind": "textSpan",
        "startOffset": 10,
        "endOffset": 14,
    }


def _address(
    selector: object = None,
    *,
    occurrence_id: str | None = "occurrence:1",
) -> CitationAddressV1:
    return CitationAddressV1(
        evidence_version_id="evidence:v1",
        structure_revision_id="structure:v1",
        projection_revision_id="projection:reviewer:v1",
        root_anchor_id="anchor:root",
        anchor_id="anchor:limitation",
        occurrence_id=occurrence_id,
        selector=_node_selector() if selector is None else selector,  # type: ignore[arg-type]
        exact_quote_sha256="4" * 64,
        projection_profile_id="reviewer-markdown",
        projection_profile_version="1",
        projection_payload_sha256="5" * 64,
        admitted_by_tool_call_id="tool-call:17",
    )


@pytest.mark.parametrize(
    "selector",
    [
        _node_selector(),
        _line_selector(),
        _text_selector(),
        _section_selector(),
        _table_selector(),
        _page_selector(),
        _media_selector(),
    ],
)
def test_citation_address_round_trips_each_closed_selector(selector: object) -> None:
    address = _address(selector)

    assert CitationAddressV1.from_json_obj(address.to_json_obj()) == address
    assert address.to_json_obj()["selector"]["kind"] in {  # type: ignore[index]
        "node",
        "lineRange",
        "textSpan",
        "section",
        "tableRange",
        "pageRegion",
        "mediaRegion",
    }
    assert len(address.digest) == 64


@pytest.mark.parametrize(
    "selector",
    [
        _node_selector(),
        _line_selector(),
        _text_selector(),
        _section_selector(),
        _table_selector(),
        _page_selector(),
        _media_selector(),
    ],
)
def test_citation_address_rejects_selector_subclasses_before_serialization(
    selector: object,
) -> None:
    exact_address = _address(selector)
    assert CitationAddressV1.from_json_obj(exact_address.to_json_obj()) == exact_address
    selector_type = type(selector)
    selector_subclass = type(f"Adversarial{selector_type.__name__}", (selector_type,), {})
    subclass_value = selector_subclass(
        **{field.name: getattr(selector, field.name) for field in fields(selector)}
    )

    def fail_if_serialized(_value: object) -> object:
        raise AssertionError("selector subclass was serialized")

    selector_subclass.to_json_obj = fail_if_serialized

    with pytest.raises(ContractValidationError, match="selector"):
        _address(subclass_value)


@pytest.mark.parametrize(
    ("value", "attribute"),
    [
        (_node_selector(), "anchor_id"),
        (_line_selector(), "start_line"),
        (_text_selector(), "end_offset"),
        (_address(), "anchor_id"),
    ],
)
def test_citation_types_are_frozen_and_slotted(value: object, attribute: str) -> None:
    assert not hasattr(value, "__dict__")

    with pytest.raises(FrozenInstanceError):
        setattr(value, attribute, "mutated")


@pytest.mark.parametrize(
    ("selector", "expected"),
    [
        (_node_selector(), {"kind": "node", "anchorId": "anchor:limitation"}),
        (_line_selector(), {"kind": "lineRange", "startLine": 88, "endLine": 103}),
        (_text_selector(), {"kind": "textSpan", "startOffset": 120, "endOffset": 188}),
    ],
)
def test_selectors_emit_exact_closed_camel_case_wire_shapes(
    selector: object,
    expected: dict[str, object],
) -> None:
    assert selector.to_json_obj() == expected  # type: ignore[attr-defined]


def test_address_emits_exact_closed_camel_case_wire_shape() -> None:
    address = _address(_line_selector())

    assert address.to_json_obj() == {
        "schemaVersion": 1,
        "kind": "citationAddress",
        "evidenceVersionId": "evidence:v1",
        "structureRevisionId": "structure:v1",
        "projectionRevisionId": "projection:reviewer:v1",
        "rootAnchorId": "anchor:root",
        "anchorId": "anchor:limitation",
        "occurrenceId": "occurrence:1",
        "selector": {"kind": "lineRange", "startLine": 88, "endLine": 103},
        "exactQuoteSha256": "4" * 64,
        "projectionProfileId": "reviewer-markdown",
        "projectionProfileVersion": "1",
        "projectionPayloadSha256": "5" * 64,
        "admittedByToolCallId": "tool-call:17",
    }


def test_to_json_obj_returns_fresh_mutable_selector_and_address_payloads() -> None:
    selector = _node_selector()
    address = _address(selector)

    selector_first = selector.to_json_obj()
    selector_second = selector.to_json_obj()
    assert selector_first is not selector_second
    selector_first["anchorId"] = "anchor:mutated"
    assert NodeSelectorV1.from_json_obj(selector_second) == selector

    address_first = address.to_json_obj()
    address_second = address.to_json_obj()
    assert address_first is not address_second
    assert address_first["selector"] is not address_second["selector"]  # type: ignore[index]
    address_first["selector"]["anchorId"] = "anchor:mutated"  # type: ignore[index]
    assert CitationAddressV1.from_json_obj(address_second) == address


@pytest.mark.parametrize(
    ("payload", "missing_key", "unknown_key", "parser"),
    [
        (
            _node_selector().to_json_obj(),
            "anchorId",
            "unexpected",
            NodeSelectorV1.from_json_obj,
        ),
        (
            _line_selector().to_json_obj(),
            "startLine",
            "unexpected",
            LineRangeSelectorV1.from_json_obj,
        ),
        (
            _text_selector().to_json_obj(),
            "endOffset",
            "unexpected",
            TextSpanSelectorV1.from_json_obj,
        ),
    ],
)
def test_selector_from_json_rejects_missing_and_unknown_fields(
    payload: dict[str, object],
    missing_key: str,
    unknown_key: str,
    parser: object,
) -> None:
    payload_missing = dict(payload)
    payload_missing.pop(missing_key)
    with pytest.raises(ContractValidationError):
        parser(payload_missing)  # type: ignore[operator]

    payload_unknown = dict(payload)
    payload_unknown[unknown_key] = "value"
    with pytest.raises(ContractValidationError):
        parser(payload_unknown)  # type: ignore[operator]


def test_address_from_json_rejects_missing_and_unknown_fields() -> None:
    payload = _address().to_json_obj()

    payload_missing = dict(payload)
    payload_missing.pop("projectionPayloadSha256")
    with pytest.raises(ContractValidationError):
        CitationAddressV1.from_json_obj(payload_missing)

    payload_unknown = dict(payload)
    payload_unknown["unexpected"] = "value"
    with pytest.raises(ContractValidationError):
        CitationAddressV1.from_json_obj(payload_unknown)


@pytest.mark.parametrize(
    "factory",
    [
        lambda: LineRangeSelectorV1(0, 1),
        lambda: LineRangeSelectorV1(5, 4),
        lambda: TextSpanSelectorV1(-1, 0),
        lambda: TextSpanSelectorV1(3, 3),
    ],
)
def test_citation_selectors_reject_empty_or_reversed_ranges(factory: object) -> None:
    with pytest.raises(ContractValidationError):
        factory()  # type: ignore[operator]


@pytest.mark.parametrize(
    "factory",
    [
        lambda: LineRangeSelectorV1(start_line=2**53, end_line=2**53),
        lambda: TextSpanSelectorV1(start_offset=0, end_offset=2**53),
    ],
)
def test_citation_selectors_reject_unsafe_integer_bounds(factory: object) -> None:
    with pytest.raises(ContractValidationError, match="safe"):
        factory()  # type: ignore[operator]


@pytest.mark.parametrize(
    "change",
    [
        {"evidence_version_id": "e\u0301"},
        {"structure_revision_id": ""},
        {"projection_revision_id": "bad id"},
        {"root_anchor_id": "anchor/\u0301"},
        {"anchor_id": "anchor/\u0301"},
        {"projection_profile_id": ""},
        {"projection_profile_version": "e\u0301"},
        {"admitted_by_tool_call_id": ""},
        {"occurrence_id": ""},
        {"exact_quote_sha256": "A" * 64},
        {"projection_payload_sha256": "A" * 64},
    ],
)
def test_citation_address_rejects_invalid_identifiers_and_optional_values(
    change: dict[str, object],
) -> None:
    with pytest.raises(ContractValidationError):
        replace(_address(), **change)  # type: ignore[arg-type]


def test_node_selector_anchor_must_match_citation_address_anchor() -> None:
    with pytest.raises(ContractValidationError, match="anchor"):
        _address(NodeSelectorV1(anchor_id="anchor:elsewhere"))


def test_citation_address_rejects_unknown_selector_kind() -> None:
    payload = _address().to_json_obj()
    payload["selector"] = {"kind": "xpath", "value": "//body"}

    with pytest.raises(ContractValidationError, match="selector"):
        CitationAddressV1.from_json_obj(payload)


def test_citation_address_digest_changes_when_selector_changes() -> None:
    address = _address(_line_selector())

    assert replace(address, selector=LineRangeSelectorV1(89, 103)).digest != address.digest
