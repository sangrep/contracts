"""Version-qualified citation-address contracts for wire schema v1."""

from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar, Self, TypeAlias

from .canonical import ContractValidationError, JsonValue, canonical_json_sha256, require_sha256
from .filesystem import require_safe_relative_path_label_v1
from .identity import (
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


def _require_positive_int(value: object, *, field_name: str) -> int:
    number = _require_non_negative_int(value, field_name=field_name)
    if number < 1:
        raise ContractValidationError(f"{field_name} must be at least 1.")
    return number


def _require_ordinal_path(value: object, *, field_name: str) -> tuple[int, ...]:
    if type(value) is not tuple:
        raise ContractValidationError(f"{field_name} must be a tuple of coordinates.")
    result = tuple(_require_non_negative_int(item, field_name=field_name) for item in value)
    if not result:
        raise ContractValidationError(f"{field_name} must not be empty.")
    return result


def _parse_ordinal_path(value: object, *, field_name: str) -> tuple[int, ...]:
    if type(value) is not list:
        raise ContractValidationError(f"{field_name} must be a JSON array.")
    return _require_ordinal_path(tuple(value), field_name=field_name)


def _require_ordered_positive_range(start: int, end: int, *, field_name: str) -> None:
    start_value = _require_positive_int(start, field_name=f"{field_name}.start")
    end_value = _require_positive_int(end, field_name=f"{field_name}.end")
    if end_value < start_value:
        raise ContractValidationError(f"{field_name} must be ordered and non-empty.")


def _require_non_empty_offset_span(start: int, end: int, *, field_name: str) -> None:
    start_value = _require_non_negative_int(start, field_name=f"{field_name}.start")
    end_value = _require_non_negative_int(end, field_name=f"{field_name}.end")
    if end_value <= start_value:
        raise ContractValidationError(f"{field_name} must be ordered and non-empty.")


def _require_coordinate_profile(value: object, *, field_name: str) -> str:
    return _require_identifier(
        _require_string(value, field_name=field_name),
        field_name=field_name,
    )


def _require_region_coordinates(
    *,
    x: int,
    y: int,
    width: int,
    height: int,
    coordinate_profile: str,
) -> None:
    _require_non_negative_int(x, field_name="x")
    _require_non_negative_int(y, field_name="y")
    _require_positive_int(width, field_name="width")
    _require_positive_int(height, field_name="height")
    _require_coordinate_profile(coordinate_profile, field_name="coordinate_profile")


def _require_optional_sha256(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    return require_sha256(_require_string(value, field_name=field_name), field_name=field_name)


@dataclass(frozen=True, slots=True)
class FilesystemInventoryEntryLocatorV1:
    snapshot_id: str
    entry_id: str

    _WIRE_KIND: ClassVar[str] = "filesystemInventoryEntry"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset({"kind", "snapshotId", "entryId"})

    def __post_init__(self) -> None:
        _require_identifier(self.snapshot_id, field_name="snapshot_id")
        _require_identifier(self.entry_id, field_name="entry_id")
        _validate_canonical_wire(self.to_json_obj())

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {"kind": self._WIRE_KIND, "snapshotId": self.snapshot_id, "entryId": self.entry_id}

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        try:
            payload = _require_exact_wire_fields(
                _require_json_object(value, field_name=cls._WIRE_KIND),
                expected_keys=cls._WIRE_KEYS,
                field_name=cls._WIRE_KIND,
            )
            _require_kind(payload["kind"], expected_kind=cls._WIRE_KIND)
            return cls(
                snapshot_id=_require_identifier(
                    _require_string(payload["snapshotId"], field_name="snapshotId"),
                    field_name="snapshotId",
                ),
                entry_id=_require_identifier(
                    _require_string(payload["entryId"], field_name="entryId"),
                    field_name="entryId",
                ),
            )
        except ContractValidationError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError(f"{cls._WIRE_KIND} is malformed.") from None


@dataclass(frozen=True, slots=True)
class TextFileLocatorV1:
    source_version_id: str
    relative_path: str
    start_line: int
    end_line: int
    start_offset: int
    end_offset: int

    _WIRE_KIND: ClassVar[str] = "textFile"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "kind",
            "sourceVersionId",
            "relativePath",
            "startLine",
            "endLine",
            "startOffset",
            "endOffset",
        }
    )

    def __post_init__(self) -> None:
        _require_identifier(self.source_version_id, field_name="source_version_id")
        require_safe_relative_path_label_v1(
            self.relative_path,
            is_root=False,
            field_name="relative_path",
        )
        _require_ordered_positive_range(
            self.start_line,
            self.end_line,
            field_name="line_range",
        )
        _require_non_empty_offset_span(
            self.start_offset,
            self.end_offset,
            field_name="offset_span",
        )
        _validate_canonical_wire(self.to_json_obj())

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "kind": self._WIRE_KIND,
            "sourceVersionId": self.source_version_id,
            "relativePath": self.relative_path,
            "startLine": self.start_line,
            "endLine": self.end_line,
            "startOffset": self.start_offset,
            "endOffset": self.end_offset,
        }

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        try:
            payload = _require_exact_wire_fields(
                _require_json_object(value, field_name=cls._WIRE_KIND),
                expected_keys=cls._WIRE_KEYS,
                field_name=cls._WIRE_KIND,
            )
            _require_kind(payload["kind"], expected_kind=cls._WIRE_KIND)
            return cls(
                source_version_id=_require_identifier(
                    _require_string(payload["sourceVersionId"], field_name="sourceVersionId"),
                    field_name="sourceVersionId",
                ),
                relative_path=_require_string(payload["relativePath"], field_name="relativePath"),
                start_line=_require_positive_int(payload["startLine"], field_name="startLine"),
                end_line=_require_positive_int(payload["endLine"], field_name="endLine"),
                start_offset=_require_non_negative_int(
                    payload["startOffset"],
                    field_name="startOffset",
                ),
                end_offset=_require_non_negative_int(payload["endOffset"], field_name="endOffset"),
            )
        except ContractValidationError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError(f"{cls._WIRE_KIND} is malformed.") from None


@dataclass(frozen=True, slots=True)
class SectionLocatorV1:
    source_version_id: str
    section_ordinal_path: tuple[int, ...]

    _WIRE_KIND: ClassVar[str] = "section"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {"kind", "sourceVersionId", "sectionOrdinalPath"}
    )

    def __post_init__(self) -> None:
        _require_identifier(self.source_version_id, field_name="source_version_id")
        _require_ordinal_path(self.section_ordinal_path, field_name="section_ordinal_path")
        _validate_canonical_wire(self.to_json_obj())

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "kind": self._WIRE_KIND,
            "sourceVersionId": self.source_version_id,
            "sectionOrdinalPath": list(self.section_ordinal_path),
        }

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        try:
            payload = _require_exact_wire_fields(
                _require_json_object(value, field_name=cls._WIRE_KIND),
                expected_keys=cls._WIRE_KEYS,
                field_name=cls._WIRE_KIND,
            )
            _require_kind(payload["kind"], expected_kind=cls._WIRE_KIND)
            return cls(
                source_version_id=_require_identifier(
                    _require_string(payload["sourceVersionId"], field_name="sourceVersionId"),
                    field_name="sourceVersionId",
                ),
                section_ordinal_path=_parse_ordinal_path(
                    payload["sectionOrdinalPath"],
                    field_name="sectionOrdinalPath",
                ),
            )
        except ContractValidationError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError(f"{cls._WIRE_KIND} is malformed.") from None


@dataclass(frozen=True, slots=True)
class TableRangeLocatorV1:
    source_version_id: str
    table_ordinal_path: tuple[int, ...]
    start_row: int
    end_row: int
    start_column: int
    end_column: int

    _WIRE_KIND: ClassVar[str] = "tableRange"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "kind",
            "sourceVersionId",
            "tableOrdinalPath",
            "startRow",
            "endRow",
            "startColumn",
            "endColumn",
        }
    )

    def __post_init__(self) -> None:
        _require_identifier(self.source_version_id, field_name="source_version_id")
        _require_ordinal_path(self.table_ordinal_path, field_name="table_ordinal_path")
        _require_ordered_positive_range(self.start_row, self.end_row, field_name="row_range")
        _require_ordered_positive_range(
            self.start_column,
            self.end_column,
            field_name="column_range",
        )
        _validate_canonical_wire(self.to_json_obj())

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "kind": self._WIRE_KIND,
            "sourceVersionId": self.source_version_id,
            "tableOrdinalPath": list(self.table_ordinal_path),
            "startRow": self.start_row,
            "endRow": self.end_row,
            "startColumn": self.start_column,
            "endColumn": self.end_column,
        }

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        try:
            payload = _require_exact_wire_fields(
                _require_json_object(value, field_name=cls._WIRE_KIND),
                expected_keys=cls._WIRE_KEYS,
                field_name=cls._WIRE_KIND,
            )
            _require_kind(payload["kind"], expected_kind=cls._WIRE_KIND)
            return cls(
                source_version_id=_require_identifier(
                    _require_string(payload["sourceVersionId"], field_name="sourceVersionId"),
                    field_name="sourceVersionId",
                ),
                table_ordinal_path=_parse_ordinal_path(
                    payload["tableOrdinalPath"],
                    field_name="tableOrdinalPath",
                ),
                start_row=_require_positive_int(payload["startRow"], field_name="startRow"),
                end_row=_require_positive_int(payload["endRow"], field_name="endRow"),
                start_column=_require_positive_int(
                    payload["startColumn"],
                    field_name="startColumn",
                ),
                end_column=_require_positive_int(payload["endColumn"], field_name="endColumn"),
            )
        except ContractValidationError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError(f"{cls._WIRE_KIND} is malformed.") from None


@dataclass(frozen=True, slots=True)
class PageRegionLocatorV1:
    source_version_id: str
    page_number: int
    x: int
    y: int
    width: int
    height: int
    coordinate_profile: str

    _WIRE_KIND: ClassVar[str] = "pageRegion"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "kind",
            "sourceVersionId",
            "pageNumber",
            "x",
            "y",
            "width",
            "height",
            "coordinateProfile",
        }
    )

    def __post_init__(self) -> None:
        _require_identifier(self.source_version_id, field_name="source_version_id")
        _require_positive_int(self.page_number, field_name="page_number")
        _require_region_coordinates(
            x=self.x,
            y=self.y,
            width=self.width,
            height=self.height,
            coordinate_profile=self.coordinate_profile,
        )
        _validate_canonical_wire(self.to_json_obj())

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "kind": self._WIRE_KIND,
            "sourceVersionId": self.source_version_id,
            "pageNumber": self.page_number,
            "x": self.x,
            "y": self.y,
            "width": self.width,
            "height": self.height,
            "coordinateProfile": self.coordinate_profile,
        }

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        try:
            payload = _require_exact_wire_fields(
                _require_json_object(value, field_name=cls._WIRE_KIND),
                expected_keys=cls._WIRE_KEYS,
                field_name=cls._WIRE_KIND,
            )
            _require_kind(payload["kind"], expected_kind=cls._WIRE_KIND)
            return cls(
                source_version_id=_require_identifier(
                    _require_string(payload["sourceVersionId"], field_name="sourceVersionId"),
                    field_name="sourceVersionId",
                ),
                page_number=_require_positive_int(payload["pageNumber"], field_name="pageNumber"),
                x=_require_non_negative_int(payload["x"], field_name="x"),
                y=_require_non_negative_int(payload["y"], field_name="y"),
                width=_require_positive_int(payload["width"], field_name="width"),
                height=_require_positive_int(payload["height"], field_name="height"),
                coordinate_profile=_require_coordinate_profile(
                    payload["coordinateProfile"],
                    field_name="coordinateProfile",
                ),
            )
        except ContractValidationError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError(f"{cls._WIRE_KIND} is malformed.") from None


@dataclass(frozen=True, slots=True)
class MediaRegionLocatorV1:
    source_version_id: str
    media_object_id: str
    x: int
    y: int
    width: int
    height: int
    coordinate_profile: str

    _WIRE_KIND: ClassVar[str] = "mediaRegion"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "kind",
            "sourceVersionId",
            "mediaObjectId",
            "x",
            "y",
            "width",
            "height",
            "coordinateProfile",
        }
    )

    def __post_init__(self) -> None:
        _require_identifier(self.source_version_id, field_name="source_version_id")
        _require_identifier(self.media_object_id, field_name="media_object_id")
        _require_region_coordinates(
            x=self.x,
            y=self.y,
            width=self.width,
            height=self.height,
            coordinate_profile=self.coordinate_profile,
        )
        _validate_canonical_wire(self.to_json_obj())

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "kind": self._WIRE_KIND,
            "sourceVersionId": self.source_version_id,
            "mediaObjectId": self.media_object_id,
            "x": self.x,
            "y": self.y,
            "width": self.width,
            "height": self.height,
            "coordinateProfile": self.coordinate_profile,
        }

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        try:
            payload = _require_exact_wire_fields(
                _require_json_object(value, field_name=cls._WIRE_KIND),
                expected_keys=cls._WIRE_KEYS,
                field_name=cls._WIRE_KIND,
            )
            _require_kind(payload["kind"], expected_kind=cls._WIRE_KIND)
            return cls(
                source_version_id=_require_identifier(
                    _require_string(payload["sourceVersionId"], field_name="sourceVersionId"),
                    field_name="sourceVersionId",
                ),
                media_object_id=_require_identifier(
                    _require_string(payload["mediaObjectId"], field_name="mediaObjectId"),
                    field_name="mediaObjectId",
                ),
                x=_require_non_negative_int(payload["x"], field_name="x"),
                y=_require_non_negative_int(payload["y"], field_name="y"),
                width=_require_positive_int(payload["width"], field_name="width"),
                height=_require_positive_int(payload["height"], field_name="height"),
                coordinate_profile=_require_coordinate_profile(
                    payload["coordinateProfile"],
                    field_name="coordinateProfile",
                ),
            )
        except ContractValidationError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError(f"{cls._WIRE_KIND} is malformed.") from None


SourceLocatorV1: TypeAlias = (
    FilesystemInventoryEntryLocatorV1
    | TextFileLocatorV1
    | SectionLocatorV1
    | TableRangeLocatorV1
    | PageRegionLocatorV1
    | MediaRegionLocatorV1
)


def source_locator_from_json_obj(value: object) -> SourceLocatorV1:
    payload = _require_json_object(value, field_name="source_locator")
    kind = payload.get("kind")
    if kind == FilesystemInventoryEntryLocatorV1._WIRE_KIND:
        return FilesystemInventoryEntryLocatorV1.from_json_obj(payload)
    if kind == TextFileLocatorV1._WIRE_KIND:
        return TextFileLocatorV1.from_json_obj(payload)
    if kind == SectionLocatorV1._WIRE_KIND:
        return SectionLocatorV1.from_json_obj(payload)
    if kind == TableRangeLocatorV1._WIRE_KIND:
        return TableRangeLocatorV1.from_json_obj(payload)
    if kind == PageRegionLocatorV1._WIRE_KIND:
        return PageRegionLocatorV1.from_json_obj(payload)
    if kind == MediaRegionLocatorV1._WIRE_KIND:
        return MediaRegionLocatorV1.from_json_obj(payload)
    raise ContractValidationError("source locator contains an unknown kind.")


@dataclass(frozen=True, slots=True)
class NodeSelectorV1:
    anchor_id: str

    _WIRE_KIND: ClassVar[str] = "node"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset({"kind", "anchorId"})

    def __post_init__(self) -> None:
        _require_identifier(self.anchor_id, field_name="anchor_id")
        _validate_canonical_wire(self.to_json_obj())

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {"kind": self._WIRE_KIND, "anchorId": self.anchor_id}

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        try:
            payload = _require_exact_wire_fields(
                _require_json_object(value, field_name=cls._WIRE_KIND),
                expected_keys=cls._WIRE_KEYS,
                field_name=cls._WIRE_KIND,
            )
            _require_kind(payload["kind"], expected_kind=cls._WIRE_KIND)
            return cls(
                anchor_id=_require_identifier(
                    _require_string(payload["anchorId"], field_name="anchorId"),
                    field_name="anchorId",
                )
            )
        except ContractValidationError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError(f"{cls._WIRE_KIND} is malformed.") from None


@dataclass(frozen=True, slots=True)
class LineRangeSelectorV1:
    start_line: int
    end_line: int

    _WIRE_KIND: ClassVar[str] = "lineRange"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset({"kind", "startLine", "endLine"})

    def __post_init__(self) -> None:
        start_line = _require_positive_int(self.start_line, field_name="start_line")
        end_line = _require_positive_int(self.end_line, field_name="end_line")
        if end_line < start_line:
            raise ContractValidationError("line range must be ordered and non-empty.")
        _validate_canonical_wire(self.to_json_obj())

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "kind": self._WIRE_KIND,
            "startLine": self.start_line,
            "endLine": self.end_line,
        }

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        try:
            payload = _require_exact_wire_fields(
                _require_json_object(value, field_name=cls._WIRE_KIND),
                expected_keys=cls._WIRE_KEYS,
                field_name=cls._WIRE_KIND,
            )
            _require_kind(payload["kind"], expected_kind=cls._WIRE_KIND)
            return cls(
                start_line=_require_positive_int(payload["startLine"], field_name="startLine"),
                end_line=_require_positive_int(payload["endLine"], field_name="endLine"),
            )
        except ContractValidationError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError(f"{cls._WIRE_KIND} is malformed.") from None


@dataclass(frozen=True, slots=True)
class TextSpanSelectorV1:
    start_offset: int
    end_offset: int

    _WIRE_KIND: ClassVar[str] = "textSpan"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset({"kind", "startOffset", "endOffset"})

    def __post_init__(self) -> None:
        start_offset = _require_non_negative_int(self.start_offset, field_name="start_offset")
        end_offset = _require_non_negative_int(self.end_offset, field_name="end_offset")
        if end_offset <= start_offset:
            raise ContractValidationError("text span must be ordered and non-empty.")
        _validate_canonical_wire(self.to_json_obj())

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "kind": self._WIRE_KIND,
            "startOffset": self.start_offset,
            "endOffset": self.end_offset,
        }

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        try:
            payload = _require_exact_wire_fields(
                _require_json_object(value, field_name=cls._WIRE_KIND),
                expected_keys=cls._WIRE_KEYS,
                field_name=cls._WIRE_KIND,
            )
            _require_kind(payload["kind"], expected_kind=cls._WIRE_KIND)
            return cls(
                start_offset=_require_non_negative_int(
                    payload["startOffset"],
                    field_name="startOffset",
                ),
                end_offset=_require_non_negative_int(payload["endOffset"], field_name="endOffset"),
            )
        except ContractValidationError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError(f"{cls._WIRE_KIND} is malformed.") from None


@dataclass(frozen=True, slots=True)
class SectionSelectorV1:
    section_ordinal_path: tuple[int, ...]

    _WIRE_KIND: ClassVar[str] = "section"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset({"kind", "sectionOrdinalPath"})

    def __post_init__(self) -> None:
        _require_ordinal_path(self.section_ordinal_path, field_name="section_ordinal_path")
        _validate_canonical_wire(self.to_json_obj())

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {"kind": self._WIRE_KIND, "sectionOrdinalPath": list(self.section_ordinal_path)}

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        try:
            payload = _require_exact_wire_fields(
                _require_json_object(value, field_name=cls._WIRE_KIND),
                expected_keys=cls._WIRE_KEYS,
                field_name=cls._WIRE_KIND,
            )
            _require_kind(payload["kind"], expected_kind=cls._WIRE_KIND)
            return cls(
                section_ordinal_path=_parse_ordinal_path(
                    payload["sectionOrdinalPath"],
                    field_name="sectionOrdinalPath",
                )
            )
        except ContractValidationError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError(f"{cls._WIRE_KIND} is malformed.") from None


@dataclass(frozen=True, slots=True)
class TableRangeSelectorV1:
    table_ordinal_path: tuple[int, ...]
    start_row: int
    end_row: int
    start_column: int
    end_column: int

    _WIRE_KIND: ClassVar[str] = "tableRange"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {"kind", "tableOrdinalPath", "startRow", "endRow", "startColumn", "endColumn"}
    )

    def __post_init__(self) -> None:
        _require_ordinal_path(self.table_ordinal_path, field_name="table_ordinal_path")
        _require_ordered_positive_range(self.start_row, self.end_row, field_name="row_range")
        _require_ordered_positive_range(
            self.start_column,
            self.end_column,
            field_name="column_range",
        )
        _validate_canonical_wire(self.to_json_obj())

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "kind": self._WIRE_KIND,
            "tableOrdinalPath": list(self.table_ordinal_path),
            "startRow": self.start_row,
            "endRow": self.end_row,
            "startColumn": self.start_column,
            "endColumn": self.end_column,
        }

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        try:
            payload = _require_exact_wire_fields(
                _require_json_object(value, field_name=cls._WIRE_KIND),
                expected_keys=cls._WIRE_KEYS,
                field_name=cls._WIRE_KIND,
            )
            _require_kind(payload["kind"], expected_kind=cls._WIRE_KIND)
            return cls(
                table_ordinal_path=_parse_ordinal_path(
                    payload["tableOrdinalPath"],
                    field_name="tableOrdinalPath",
                ),
                start_row=_require_positive_int(payload["startRow"], field_name="startRow"),
                end_row=_require_positive_int(payload["endRow"], field_name="endRow"),
                start_column=_require_positive_int(
                    payload["startColumn"],
                    field_name="startColumn",
                ),
                end_column=_require_positive_int(payload["endColumn"], field_name="endColumn"),
            )
        except ContractValidationError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError(f"{cls._WIRE_KIND} is malformed.") from None


@dataclass(frozen=True, slots=True)
class PageRegionSelectorV1:
    page_number: int
    x: int
    y: int
    width: int
    height: int
    coordinate_profile: str

    _WIRE_KIND: ClassVar[str] = "pageRegion"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {"kind", "pageNumber", "x", "y", "width", "height", "coordinateProfile"}
    )

    def __post_init__(self) -> None:
        _require_positive_int(self.page_number, field_name="page_number")
        _require_region_coordinates(
            x=self.x,
            y=self.y,
            width=self.width,
            height=self.height,
            coordinate_profile=self.coordinate_profile,
        )
        _validate_canonical_wire(self.to_json_obj())

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "kind": self._WIRE_KIND,
            "pageNumber": self.page_number,
            "x": self.x,
            "y": self.y,
            "width": self.width,
            "height": self.height,
            "coordinateProfile": self.coordinate_profile,
        }

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        try:
            payload = _require_exact_wire_fields(
                _require_json_object(value, field_name=cls._WIRE_KIND),
                expected_keys=cls._WIRE_KEYS,
                field_name=cls._WIRE_KIND,
            )
            _require_kind(payload["kind"], expected_kind=cls._WIRE_KIND)
            return cls(
                page_number=_require_positive_int(payload["pageNumber"], field_name="pageNumber"),
                x=_require_non_negative_int(payload["x"], field_name="x"),
                y=_require_non_negative_int(payload["y"], field_name="y"),
                width=_require_positive_int(payload["width"], field_name="width"),
                height=_require_positive_int(payload["height"], field_name="height"),
                coordinate_profile=_require_coordinate_profile(
                    payload["coordinateProfile"],
                    field_name="coordinateProfile",
                ),
            )
        except ContractValidationError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError(f"{cls._WIRE_KIND} is malformed.") from None


@dataclass(frozen=True, slots=True)
class MediaRegionSelectorV1:
    media_object_id: str
    x: int
    y: int
    width: int
    height: int
    coordinate_profile: str

    _WIRE_KIND: ClassVar[str] = "mediaRegion"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {"kind", "mediaObjectId", "x", "y", "width", "height", "coordinateProfile"}
    )

    def __post_init__(self) -> None:
        _require_identifier(self.media_object_id, field_name="media_object_id")
        _require_region_coordinates(
            x=self.x,
            y=self.y,
            width=self.width,
            height=self.height,
            coordinate_profile=self.coordinate_profile,
        )
        _validate_canonical_wire(self.to_json_obj())

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "kind": self._WIRE_KIND,
            "mediaObjectId": self.media_object_id,
            "x": self.x,
            "y": self.y,
            "width": self.width,
            "height": self.height,
            "coordinateProfile": self.coordinate_profile,
        }

    @classmethod
    def from_json_obj(cls, value: object) -> Self:
        try:
            payload = _require_exact_wire_fields(
                _require_json_object(value, field_name=cls._WIRE_KIND),
                expected_keys=cls._WIRE_KEYS,
                field_name=cls._WIRE_KIND,
            )
            _require_kind(payload["kind"], expected_kind=cls._WIRE_KIND)
            return cls(
                media_object_id=_require_identifier(
                    _require_string(payload["mediaObjectId"], field_name="mediaObjectId"),
                    field_name="mediaObjectId",
                ),
                x=_require_non_negative_int(payload["x"], field_name="x"),
                y=_require_non_negative_int(payload["y"], field_name="y"),
                width=_require_positive_int(payload["width"], field_name="width"),
                height=_require_positive_int(payload["height"], field_name="height"),
                coordinate_profile=_require_coordinate_profile(
                    payload["coordinateProfile"],
                    field_name="coordinateProfile",
                ),
            )
        except ContractValidationError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError(f"{cls._WIRE_KIND} is malformed.") from None


CitationSelectorV1: TypeAlias = (
    NodeSelectorV1
    | LineRangeSelectorV1
    | TextSpanSelectorV1
    | SectionSelectorV1
    | TableRangeSelectorV1
    | PageRegionSelectorV1
    | MediaRegionSelectorV1
)


def _selector_from_json_obj(value: object) -> CitationSelectorV1:
    payload = _require_json_object(value, field_name="selector")
    kind = payload.get("kind")
    if kind == NodeSelectorV1._WIRE_KIND:
        return NodeSelectorV1.from_json_obj(payload)
    if kind == LineRangeSelectorV1._WIRE_KIND:
        return LineRangeSelectorV1.from_json_obj(payload)
    if kind == TextSpanSelectorV1._WIRE_KIND:
        return TextSpanSelectorV1.from_json_obj(payload)
    if kind == SectionSelectorV1._WIRE_KIND:
        return SectionSelectorV1.from_json_obj(payload)
    if kind == TableRangeSelectorV1._WIRE_KIND:
        return TableRangeSelectorV1.from_json_obj(payload)
    if kind == PageRegionSelectorV1._WIRE_KIND:
        return PageRegionSelectorV1.from_json_obj(payload)
    if kind == MediaRegionSelectorV1._WIRE_KIND:
        return MediaRegionSelectorV1.from_json_obj(payload)
    raise ContractValidationError("selector contains an unknown kind.")


@dataclass(frozen=True, slots=True)
class CitationAddressV1:
    evidence_version_id: str
    structure_revision_id: str
    projection_revision_id: str
    root_anchor_id: str
    anchor_id: str
    occurrence_id: str | None
    selector: CitationSelectorV1
    exact_quote_sha256: str | None
    projection_profile_id: str
    projection_profile_version: str
    projection_payload_sha256: str
    admitted_by_tool_call_id: str

    _WIRE_KIND: ClassVar[str] = "citationAddress"
    _WIRE_KEYS: ClassVar[frozenset[str]] = frozenset(
        {
            "schemaVersion",
            "kind",
            "evidenceVersionId",
            "structureRevisionId",
            "projectionRevisionId",
            "rootAnchorId",
            "anchorId",
            "occurrenceId",
            "selector",
            "exactQuoteSha256",
            "projectionProfileId",
            "projectionProfileVersion",
            "projectionPayloadSha256",
            "admittedByToolCallId",
        }
    )

    def __post_init__(self) -> None:
        _require_identifier(self.evidence_version_id, field_name="evidence_version_id")
        _require_identifier(self.structure_revision_id, field_name="structure_revision_id")
        _require_identifier(self.projection_revision_id, field_name="projection_revision_id")
        _require_identifier(self.root_anchor_id, field_name="root_anchor_id")
        _require_identifier(self.anchor_id, field_name="anchor_id")
        _require_optional_identifier(self.occurrence_id, field_name="occurrence_id")
        if type(self.selector) not in (
            NodeSelectorV1,
            LineRangeSelectorV1,
            TextSpanSelectorV1,
            SectionSelectorV1,
            TableRangeSelectorV1,
            PageRegionSelectorV1,
            MediaRegionSelectorV1,
        ):
            raise ContractValidationError("selector contains an unknown kind.")
        if isinstance(self.selector, NodeSelectorV1) and self.selector.anchor_id != self.anchor_id:
            raise ContractValidationError("selector anchor must equal anchor_id.")
        _require_optional_sha256(self.exact_quote_sha256, field_name="exact_quote_sha256")
        _require_identifier(self.projection_profile_id, field_name="projection_profile_id")
        _require_identifier(
            self.projection_profile_version,
            field_name="projection_profile_version",
        )
        require_sha256(
            self.projection_payload_sha256,
            field_name="projection_payload_sha256",
        )
        _require_identifier(self.admitted_by_tool_call_id, field_name="admitted_by_tool_call_id")
        _validate_canonical_wire(self.to_json_obj())

    def to_json_obj(self) -> dict[str, JsonValue]:
        return {
            "schemaVersion": 1,
            "kind": self._WIRE_KIND,
            "evidenceVersionId": self.evidence_version_id,
            "structureRevisionId": self.structure_revision_id,
            "projectionRevisionId": self.projection_revision_id,
            "rootAnchorId": self.root_anchor_id,
            "anchorId": self.anchor_id,
            "occurrenceId": self.occurrence_id,
            "selector": self.selector.to_json_obj(),
            "exactQuoteSha256": self.exact_quote_sha256,
            "projectionProfileId": self.projection_profile_id,
            "projectionProfileVersion": self.projection_profile_version,
            "projectionPayloadSha256": self.projection_payload_sha256,
            "admittedByToolCallId": self.admitted_by_tool_call_id,
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
                        payload["structureRevisionId"],
                        field_name="structureRevisionId",
                    ),
                    field_name="structureRevisionId",
                ),
                projection_revision_id=_require_identifier(
                    _require_string(
                        payload["projectionRevisionId"],
                        field_name="projectionRevisionId",
                    ),
                    field_name="projectionRevisionId",
                ),
                root_anchor_id=_require_identifier(
                    _require_string(payload["rootAnchorId"], field_name="rootAnchorId"),
                    field_name="rootAnchorId",
                ),
                anchor_id=_require_identifier(
                    _require_string(payload["anchorId"], field_name="anchorId"),
                    field_name="anchorId",
                ),
                occurrence_id=_require_optional_identifier(
                    payload["occurrenceId"],
                    field_name="occurrenceId",
                ),
                selector=_selector_from_json_obj(payload["selector"]),
                exact_quote_sha256=_require_optional_sha256(
                    payload["exactQuoteSha256"],
                    field_name="exactQuoteSha256",
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
                projection_payload_sha256=require_sha256(
                    _require_string(
                        payload["projectionPayloadSha256"],
                        field_name="projectionPayloadSha256",
                    ),
                    field_name="projectionPayloadSha256",
                ),
                admitted_by_tool_call_id=_require_identifier(
                    _require_string(
                        payload["admittedByToolCallId"],
                        field_name="admittedByToolCallId",
                    ),
                    field_name="admittedByToolCallId",
                ),
            )
        except ContractValidationError:
            raise
        except (KeyError, TypeError, ValueError):
            raise ContractValidationError(f"{cls._WIRE_KIND} is malformed.") from None

    @property
    def digest(self) -> str:
        return canonical_json_sha256(self.to_json_obj())


__all__ = (
    "CitationAddressV1",
    "CitationSelectorV1",
    "FilesystemInventoryEntryLocatorV1",
    "LineRangeSelectorV1",
    "MediaRegionLocatorV1",
    "MediaRegionSelectorV1",
    "NodeSelectorV1",
    "PageRegionLocatorV1",
    "PageRegionSelectorV1",
    "SectionLocatorV1",
    "SectionSelectorV1",
    "SourceLocatorV1",
    "TableRangeLocatorV1",
    "TableRangeSelectorV1",
    "TextFileLocatorV1",
    "TextSpanSelectorV1",
    "source_locator_from_json_obj",
)
