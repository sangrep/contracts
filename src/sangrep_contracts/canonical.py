"""Bounded canonical JSON and digest rules for wire-contract v1."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass
from typing import TypeAlias, cast

JsonScalar: TypeAlias = None | bool | int | str
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]

MAX_CANONICAL_DEPTH = 64
MAX_CANONICAL_VALUES = 10_000
MAX_STRING_BYTES = 1_048_576
MAX_KEY_BYTES = 256
MAX_TOTAL_TEXT_BYTES = 8_388_608
MAX_CANONICAL_BYTES = 10_485_760
MAX_SAFE_INTEGER = 2**53 - 1


class ContractValidationError(ValueError):
    """Raised when a value cannot satisfy an exact public wire contract."""


JsonObjectValue: TypeAlias = dict[str, JsonValue]
FrozenJsonScalarV1: TypeAlias = None | bool | int | str


@dataclass(frozen=True, slots=True)
class Rfc8785JsonObjectV1:
    canonical_bytes: bytes

    def __post_init__(self) -> None:
        if type(self.canonical_bytes) is not bytes:
            raise ContractValidationError("RFC 8785 JSON object bytes must be immutable bytes.")
        rfc8785_json_object_from_bytes_v1(self.canonical_bytes)


@dataclass(frozen=True, slots=True)
class FrozenJsonArrayV1:
    items: tuple[FrozenJsonValueV1, ...]

    def __post_init__(self) -> None:
        if type(self.items) is not tuple:
            raise ContractValidationError("Frozen JSON array items must be a tuple.")
        for item in self.items:
            _require_frozen_json_value_v1(item)
        canonical_json_bytes(thaw_json_value_v1(self))


@dataclass(frozen=True, slots=True)
class FrozenJsonObjectV1:
    entries: tuple[tuple[str, FrozenJsonValueV1], ...]

    def __post_init__(self) -> None:
        if type(self.entries) is not tuple:
            raise ContractValidationError("Frozen JSON object entries must be a tuple.")
        previous_sort_key: bytes | None = None
        for entry in self.entries:
            if type(entry) is not tuple or len(entry) != 2:
                raise ContractValidationError(
                    "Frozen JSON object entries must be key/value tuples."
                )
            key, item = entry
            if type(key) is not str:
                raise ContractValidationError("Frozen JSON object keys must be strings.")
            clean_key, _ = _require_nfc(
                value=key,
                field_name="JSON object key",
                maximum_bytes=MAX_KEY_BYTES,
            )
            sort_key = _utf16_key(clean_key)
            if previous_sort_key is not None and sort_key <= previous_sort_key:
                raise ContractValidationError(
                    "Frozen JSON object keys must be unique and in canonical order."
                )
            previous_sort_key = sort_key
            _require_frozen_json_value_v1(item)
        canonical_json_bytes(thaw_json_value_v1(self))


FrozenJsonValueV1: TypeAlias = FrozenJsonScalarV1 | FrozenJsonArrayV1 | FrozenJsonObjectV1


def _require_frozen_json_value_v1(value: object) -> None:
    if value is None or type(value) is bool or type(value) is int or type(value) is str:
        return
    if type(value) is FrozenJsonArrayV1 or type(value) is FrozenJsonObjectV1:
        return
    raise ContractValidationError("Frozen JSON values must contain only exact frozen JSON types.")


def _utf16_key(value: str) -> bytes:
    return value.encode("utf-16-be")


def _require_nfc(value: str, *, field_name: str, maximum_bytes: int) -> tuple[str, int]:
    if unicodedata.normalize("NFC", value) != value:
        raise ContractValidationError(f"{field_name} must use NFC Unicode.")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ContractValidationError(f"{field_name} contains an unpaired surrogate.") from error
    if len(encoded) > maximum_bytes:
        raise ContractValidationError(f"{field_name} exceeds its byte limit.")
    return value, len(encoded)


def _add_text_bytes(text_bytes: list[int], added: int) -> None:
    text_bytes[0] += added
    if text_bytes[0] > MAX_TOTAL_TEXT_BYTES:
        raise ContractValidationError("Canonical JSON exceeds the aggregate text-byte limit.")


def _normalize(
    value: JsonValue,
    *,
    depth: int,
    count: list[int],
    text_bytes: list[int],
) -> JsonValue:
    if depth > MAX_CANONICAL_DEPTH:
        raise ContractValidationError("Canonical JSON exceeds the maximum depth.")
    count[0] += 1
    if count[0] > MAX_CANONICAL_VALUES:
        raise ContractValidationError("Canonical JSON exceeds the maximum value count.")
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if abs(value) > MAX_SAFE_INTEGER:
            raise ContractValidationError("Canonical JSON integer is outside the I-JSON range.")
        return value
    if type(value) is str:
        clean, size = _require_nfc(
            value,
            field_name="JSON string",
            maximum_bytes=MAX_STRING_BYTES,
        )
        _add_text_bytes(text_bytes, size)
        return clean
    if type(value) is list:
        return [
            _normalize(item, depth=depth + 1, count=count, text_bytes=text_bytes) for item in value
        ]
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise ContractValidationError("Canonical JSON object keys must be strings.")
        clean_keys: list[str] = []
        for key in value:
            clean_key, size = _require_nfc(
                key,
                field_name="JSON object key",
                maximum_bytes=MAX_KEY_BYTES,
            )
            _add_text_bytes(text_bytes, size)
            clean_keys.append(clean_key)
        result: dict[str, JsonValue] = {}
        for key in sorted(clean_keys, key=_utf16_key):
            result[key] = _normalize(
                value[key],
                depth=depth + 1,
                count=count,
                text_bytes=text_bytes,
            )
        return result
    raise ContractValidationError(f"Unsupported canonical JSON type: {type(value).__name__}.")


def _freeze_normalized_json(value: JsonValue) -> FrozenJsonValueV1:
    if value is None or type(value) is bool or type(value) is int or type(value) is str:
        return value
    if type(value) is list:
        return FrozenJsonArrayV1(tuple(_freeze_normalized_json(item) for item in value))
    if type(value) is dict:
        return FrozenJsonObjectV1(
            tuple(
                (key, _freeze_normalized_json(value[key])) for key in sorted(value, key=_utf16_key)
            )
        )
    raise ContractValidationError(f"Unsupported canonical JSON type: {type(value).__name__}.")


def freeze_json_value_v1(value: JsonValue) -> FrozenJsonValueV1:
    normalized = _normalize(value, depth=0, count=[0], text_bytes=[0])
    return _freeze_normalized_json(normalized)


def freeze_json_object_v1(value: JsonObjectValue) -> FrozenJsonObjectV1:
    if type(value) is not dict:
        raise ContractValidationError("JSON object value must be an object.")
    frozen = freeze_json_value_v1(value)
    if type(frozen) is not FrozenJsonObjectV1:
        raise ContractValidationError("JSON object value must be an object.")
    return frozen


def thaw_json_value_v1(value: FrozenJsonValueV1) -> JsonValue:
    if value is None or type(value) is bool or type(value) is int or type(value) is str:
        return value
    if type(value) is FrozenJsonObjectV1:
        return {key: thaw_json_value_v1(item_value) for key, item_value in value.entries}
    if type(value) is FrozenJsonArrayV1:
        return [thaw_json_value_v1(item) for item in value.items]
    raise ContractValidationError("Frozen JSON value is malformed.")


def thaw_json_object_v1(value: FrozenJsonObjectV1) -> JsonObjectValue:
    thawed = thaw_json_value_v1(value)
    if type(thawed) is not dict:
        raise ContractValidationError("Frozen JSON object is malformed.")
    return thawed


def canonical_json_sha256_omitting_field_v1(value: JsonObjectValue, *, field_name: str) -> str:
    if type(value) is not dict:
        raise ContractValidationError("digest input must be a JSON object.")
    if field_name not in value:
        raise ContractValidationError(f"{field_name} must be present before digest omission.")
    omitted = dict(value)
    del omitted[field_name]
    return canonical_json_sha256(omitted)


def canonical_json_bytes(value: JsonValue) -> bytes:
    """Serialize one bounded value according to Sangrep canonical JSON v1."""

    normalized = _normalize(value, depth=0, count=[0], text_bytes=[0])
    serialized = json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(serialized) > MAX_CANONICAL_BYTES:
        raise ContractValidationError("Canonical JSON exceeds the serialized byte limit.")
    return serialized


def canonical_json_sha256(value: JsonValue) -> str:
    """Return lowercase SHA-256 for exact canonical JSON bytes."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _require_preserved_unicode(
    value: str,
    *,
    field_name: str,
    maximum_bytes: int,
) -> tuple[str, int]:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ContractValidationError(f"{field_name} contains an unpaired surrogate.") from error
    if len(encoded) > maximum_bytes:
        raise ContractValidationError(f"{field_name} exceeds its byte limit.")
    return value, len(encoded)


def _normalize_rfc8785_v1(
    value: JsonValue,
    *,
    depth: int,
    count: list[int],
    text_bytes: list[int],
) -> JsonValue:
    if depth > MAX_CANONICAL_DEPTH:
        raise ContractValidationError("RFC 8785 JSON exceeds the maximum depth.")
    count[0] += 1
    if count[0] > MAX_CANONICAL_VALUES:
        raise ContractValidationError("RFC 8785 JSON exceeds the maximum value count.")
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if abs(value) > MAX_SAFE_INTEGER:
            raise ContractValidationError("RFC 8785 JSON integer is outside the I-JSON range.")
        return value
    if type(value) is str:
        clean, size = _require_preserved_unicode(
            value,
            field_name="RFC 8785 JSON string",
            maximum_bytes=MAX_STRING_BYTES,
        )
        _add_text_bytes(text_bytes, size)
        return clean
    if type(value) is list:
        return [
            _normalize_rfc8785_v1(
                item,
                depth=depth + 1,
                count=count,
                text_bytes=text_bytes,
            )
            for item in value
        ]
    if type(value) is dict:
        if any(type(key) is not str for key in value):
            raise ContractValidationError("RFC 8785 JSON object keys must be strings.")
        clean_keys: list[str] = []
        for key in value:
            clean_key, size = _require_preserved_unicode(
                key,
                field_name="RFC 8785 JSON object key",
                maximum_bytes=MAX_KEY_BYTES,
            )
            _add_text_bytes(text_bytes, size)
            clean_keys.append(clean_key)
        return {
            key: _normalize_rfc8785_v1(
                value[key],
                depth=depth + 1,
                count=count,
                text_bytes=text_bytes,
            )
            for key in sorted(clean_keys, key=_utf16_key)
        }
    raise ContractValidationError(f"Unsupported RFC 8785 JSON type: {type(value).__name__}.")


def rfc8785_json_bytes_v1(value: JsonValue) -> bytes:
    """Serialize the bounded integer-only I-JSON subset using RFC 8785 rules."""

    normalized = _normalize_rfc8785_v1(value, depth=0, count=[0], text_bytes=[0])
    serialized = json.dumps(
        normalized,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(serialized) > MAX_CANONICAL_BYTES:
        raise ContractValidationError("RFC 8785 JSON exceeds the serialized byte limit.")
    return serialized


def rfc8785_json_sha256_v1(value: JsonValue) -> str:
    return hashlib.sha256(rfc8785_json_bytes_v1(value)).hexdigest()


def rfc8785_json_sha256_omitting_field_v1(
    value: JsonObjectValue,
    *,
    field_name: str,
) -> str:
    if type(value) is not dict:
        raise ContractValidationError("RFC 8785 digest input must be a JSON object.")
    if field_name not in value:
        raise ContractValidationError(f"{field_name} must be present before digest omission.")
    omitted = dict(value)
    del omitted[field_name]
    return rfc8785_json_sha256_v1(omitted)


def _load_bounded_json_v1(data: bytes) -> JsonValue:
    if type(data) is not bytes:
        raise ContractValidationError("RFC 8785 JSON input must be immutable bytes.")
    if len(data) > MAX_CANONICAL_BYTES:
        raise ContractValidationError("RFC 8785 JSON exceeds the serialized byte limit.")

    def parse_integer(raw: str) -> int:
        if len(raw.lstrip("-")) > 16:
            raise ContractValidationError("RFC 8785 JSON integer is outside the I-JSON range.")
        try:
            value = int(raw)
        except ValueError as error:
            raise ContractValidationError("RFC 8785 JSON integer is malformed.") from error
        if abs(value) > MAX_SAFE_INTEGER:
            raise ContractValidationError("RFC 8785 JSON integer is outside the I-JSON range.")
        return value

    def reject_constant(value: str) -> None:
        raise ContractValidationError(f"non-finite JSON constant is forbidden: {value}.")

    def object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ContractValidationError("RFC 8785 JSON contains a duplicate object key.")
            result[key] = item
        return result

    try:
        value = json.loads(
            data.decode("utf-8"),
            parse_int=parse_integer,
            parse_constant=reject_constant,
            object_pairs_hook=object_without_duplicates,
        )
    except ContractValidationError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise ContractValidationError("RFC 8785 JSON input is malformed.") from error
    return cast(JsonValue, value)


def rfc8785_json_object_from_bytes_v1(data: bytes) -> JsonObjectValue:
    value = _load_bounded_json_v1(data)
    if type(value) is not dict:
        raise ContractValidationError("RFC 8785 JSON value must be an object.")
    if rfc8785_json_bytes_v1(value) != data:
        raise ContractValidationError("JSON bytes must use canonical RFC 8785 encoding.")
    return value


def freeze_rfc8785_json_object_v1(value: JsonObjectValue) -> Rfc8785JsonObjectV1:
    if type(value) is not dict:
        raise ContractValidationError("RFC 8785 JSON value must be an object.")
    return Rfc8785JsonObjectV1(rfc8785_json_bytes_v1(value))


def thaw_rfc8785_json_object_v1(value: Rfc8785JsonObjectV1) -> JsonObjectValue:
    if type(value) is not Rfc8785JsonObjectV1:
        raise ContractValidationError("RFC 8785 frozen JSON object is malformed.")
    return rfc8785_json_object_from_bytes_v1(value.canonical_bytes)


def require_sha256(value: str, *, field_name: str) -> str:
    """Validate one lowercase SHA-256 string without normalizing it."""

    if type(value) is not str:
        raise ContractValidationError(f"{field_name} must be a lowercase SHA-256 value.")
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ContractValidationError(f"{field_name} must be a lowercase SHA-256 value.")
    return value
