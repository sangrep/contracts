from __future__ import annotations

import pytest

from sangrep_contracts import (
    ContractValidationError,
    canonical_json_bytes,
    canonical_json_sha256,
    require_sha256,
)


def test_canonical_json_orders_keys_by_utf16_and_is_utf8() -> None:
    first = {"😀": "astral", "a": [True, None, 7], "€": "bmp"}
    second = {"€": "bmp", "a": [True, None, 7], "😀": "astral"}

    expected = '{"a":[true,null,7],"€":"bmp","😀":"astral"}'.encode()
    assert canonical_json_bytes(first) == expected
    assert canonical_json_bytes(second) == expected
    assert canonical_json_sha256(first) == canonical_json_sha256(second)


@pytest.mark.parametrize(
    "value",
    [1.0, float("nan"), b"bytes", {"set"}, {1: "non-string key"}, 2**53],
)
def test_canonical_json_rejects_values_outside_the_v1_profile(value: object) -> None:
    with pytest.raises(ContractValidationError):
        canonical_json_bytes(value)  # type: ignore[arg-type]


def test_canonical_json_rejects_non_nfc_and_excessive_depth() -> None:
    with pytest.raises(ContractValidationError, match="NFC"):
        canonical_json_bytes({"value": "e\u0301"})

    nested: object = None
    for _ in range(66):
        nested = [nested]
    with pytest.raises(ContractValidationError, match="depth"):
        canonical_json_bytes(nested)  # type: ignore[arg-type]


def test_canonical_json_rejects_oversized_strings_keys_and_aggregate_text() -> None:
    with pytest.raises(ContractValidationError, match="string"):
        canonical_json_bytes("x" * (1_048_576 + 1))
    with pytest.raises(ContractValidationError, match="key"):
        canonical_json_bytes({"k" * 257: None})
    with pytest.raises(ContractValidationError, match="aggregate"):
        canonical_json_bytes(["x" * 1_048_576 for _ in range(9)])


def test_canonical_json_maps_unpaired_surrogate_keys_to_typed_failure() -> None:
    with pytest.raises(ContractValidationError, match="surrogate"):
        canonical_json_bytes({"\ud800": None})


def test_canonical_json_enforces_the_value_count_boundary() -> None:
    canonical_json_bytes([0] * 9_999)

    with pytest.raises(ContractValidationError, match="value count"):
        canonical_json_bytes([0] * 10_000)


def test_canonical_json_rejects_serialized_bytes_after_control_character_expansion() -> None:
    control_text = "\x00" * 1_048_576

    with pytest.raises(ContractValidationError, match="serialized byte"):
        canonical_json_bytes([control_text, control_text])


def test_require_sha256_accepts_a_lowercase_digest() -> None:
    digest = "a" * 64

    assert require_sha256(digest, field_name="digest") == digest


@pytest.mark.parametrize("value", ["A" * 64, "g" * 64, "a" * 63, "a" * 65, 1])
def test_require_sha256_rejects_invalid_digest_values(value: object) -> None:
    with pytest.raises(ContractValidationError):
        require_sha256(value, field_name="digest")  # type: ignore[arg-type]
