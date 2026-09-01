from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from sangrep_contracts import (
    ContractValidationError,
    FilesystemInventoryEntryLocatorV1,
    LineRangeSelectorV1,
    MediaRegionLocatorV1,
    MediaRegionSelectorV1,
    NodeSelectorV1,
    PageRegionLocatorV1,
    PageRegionSelectorV1,
    SectionLocatorV1,
    SectionSelectorV1,
    TableRangeLocatorV1,
    TableRangeSelectorV1,
    TextFileLocatorV1,
    TextSpanSelectorV1,
    source_locator_from_json_obj,
)


def test_six_source_locators_emit_exact_closed_wire_shapes() -> None:
    locators = [
        FilesystemInventoryEntryLocatorV1(snapshot_id="snapshot:v1", entry_id="entry:blocked"),
        TextFileLocatorV1("source:v1", "policy.md", 1, 3, 0, 120),
        SectionLocatorV1("source:v1", (0, 2)),
        TableRangeLocatorV1("source:v1", (1,), 1, 3, 1, 2),
        PageRegionLocatorV1("source:v1", 2, 100, 200, 900, 400, "page-unit-10000"),
        MediaRegionLocatorV1("source:v1", "media:chart:1", 50, 75, 600, 300, "media-unit-10000"),
    ]

    assert [locator.to_json_obj()["kind"] for locator in locators] == [
        "filesystemInventoryEntry",
        "textFile",
        "section",
        "tableRange",
        "pageRegion",
        "mediaRegion",
    ]
    assert [source_locator_from_json_obj(locator.to_json_obj()) for locator in locators] == locators
    for locator in locators:
        assert "schemaVersion" not in locator.to_json_obj()


def test_seven_selectors_emit_exact_closed_wire_shapes() -> None:
    selectors = [
        NodeSelectorV1(anchor_id="anchor:section"),
        LineRangeSelectorV1(2, 5),
        TextSpanSelectorV1(10, 15),
        SectionSelectorV1((0, 2)),
        TableRangeSelectorV1((1,), 1, 3, 1, 2),
        PageRegionSelectorV1(2, 100, 200, 900, 400, "page-unit-10000"),
        MediaRegionSelectorV1("media:chart:1", 50, 75, 600, 300, "media-unit-10000"),
    ]

    assert [selector.to_json_obj()["kind"] for selector in selectors] == [
        "node",
        "lineRange",
        "textSpan",
        "section",
        "tableRange",
        "pageRegion",
        "mediaRegion",
    ]
    for selector in selectors:
        assert "schemaVersion" not in selector.to_json_obj()


@pytest.mark.parametrize(
    "factory",
    [
        lambda: SectionSelectorV1(()),
        lambda: TableRangeSelectorV1((), 1, 1, 1, 1),
        lambda: TableRangeSelectorV1((0,), 0, 1, 1, 1),
        lambda: TableRangeSelectorV1((0,), 1, 1, 0, 1),
        lambda: TableRangeSelectorV1((0,), 3, 2, 1, 1),
        lambda: TableRangeSelectorV1((0,), 1, 1, 2, 1),
        lambda: TableRangeLocatorV1("source:v1", (0,), 0, 1, 1, 1),
        lambda: TableRangeLocatorV1("source:v1", (0,), 1, 1, 0, 1),
        lambda: PageRegionSelectorV1(0, 0, 0, 1, 1, "page-unit-10000"),
        lambda: PageRegionSelectorV1(1, 0, 0, 0, 1, "page-unit-10000"),
        lambda: MediaRegionSelectorV1("", 0, 0, 1, 1, "media-unit-10000"),
        lambda: MediaRegionSelectorV1("media:1", 0, 0, 1, 0, "media-unit-10000"),
        lambda: TextFileLocatorV1("source:v1", "/absolute.md", 1, 1, 0, 1),
        lambda: TextFileLocatorV1("source:v1", "policy.md", 2, 1, 0, 1),
        lambda: TextFileLocatorV1("source:v1", "policy.md", 1, 1, 5, 5),
    ],
)
def test_locators_and_rich_selectors_reject_empty_reversed_and_invalid_coordinates(
    factory: object,
) -> None:
    with pytest.raises(ContractValidationError):
        factory()  # type: ignore[operator]


def test_locator_and_selector_dispatch_reject_unknown_kind_and_embedded_schema_version() -> None:
    with pytest.raises(ContractValidationError, match="locator"):
        source_locator_from_json_obj({"kind": "extensionLocator", "value": "x"})

    with pytest.raises(ContractValidationError):
        source_locator_from_json_obj(
            {
                "kind": "section",
                "schemaVersion": 1,
                "sourceVersionId": "source:v1",
                "sectionOrdinalPath": [0],
            }
        )


def test_locators_and_selectors_are_frozen_and_slotted() -> None:
    locator = SectionLocatorV1("source:v1", (0,))
    selector = SectionSelectorV1((0,))

    assert not hasattr(locator, "__dict__")
    assert not hasattr(selector, "__dict__")
    with pytest.raises(FrozenInstanceError):
        selector.section_ordinal_path = (1,)  # type: ignore[misc]
