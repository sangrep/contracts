from __future__ import annotations

import pytest

from sangrep_contracts import (
    ContractValidationError,
    FrozenJsonArrayV1,
    FrozenJsonObjectV1,
    FrozenJsonValueV1,
    canonical_json_sha256,
    canonical_json_sha256_omitting_field_v1,
    freeze_json_object_v1,
    freeze_json_value_v1,
    thaw_json_object_v1,
    thaw_json_value_v1,
)


def test_freeze_json_value_sorts_object_keys_and_returns_deep_tuples() -> None:
    frozen = freeze_json_value_v1({"b": [2, {"a": None}], "a": True})

    assert frozen == FrozenJsonObjectV1(
        (("a", True), ("b", FrozenJsonArrayV1((2, FrozenJsonObjectV1((("a", None),))))))
    )
    assert isinstance(frozen, FrozenJsonObjectV1)
    assert canonical_json_sha256(thaw_json_value_v1(frozen)) == canonical_json_sha256(
        {"a": True, "b": [2, {"a": None}]}
    )


def test_freeze_json_value_preserves_empty_array_empty_object_and_pair_array() -> None:
    assert freeze_json_value_v1([]) == FrozenJsonArrayV1(())
    assert freeze_json_value_v1({}) == FrozenJsonObjectV1(())
    assert freeze_json_value_v1([["a", 1]]) == FrozenJsonArrayV1((FrozenJsonArrayV1(("a", 1)),))
    assert thaw_json_value_v1(FrozenJsonArrayV1(())) == []
    assert thaw_json_value_v1(FrozenJsonObjectV1(())) == {}
    assert thaw_json_value_v1(FrozenJsonArrayV1((FrozenJsonArrayV1(("a", 1)),))) == [["a", 1]]


def test_freeze_json_object_requires_object_and_exports_exact_alias_shape() -> None:
    frozen: FrozenJsonObjectV1 = freeze_json_object_v1({"text": "Scope", "marks": []})
    value: FrozenJsonValueV1 = frozen

    assert value == FrozenJsonObjectV1((("marks", FrozenJsonArrayV1(())), ("text", "Scope")))
    assert thaw_json_object_v1(frozen) == {"marks": [], "text": "Scope"}

    with pytest.raises(ContractValidationError, match="object"):
        freeze_json_object_v1(["not", "object"])  # type: ignore[arg-type]


def test_thaw_returns_fresh_mutable_containers_every_time() -> None:
    frozen = freeze_json_value_v1({"items": [{"text": "A"}]})

    first = thaw_json_value_v1(frozen)
    second = thaw_json_value_v1(frozen)

    assert first == second
    assert first is not second
    first["items"][0]["text"] = "changed"  # type: ignore[index]
    assert second == {"items": [{"text": "A"}]}


def test_freeze_rejects_non_json_values_and_canonical_bound_failures() -> None:
    with pytest.raises(ContractValidationError):
        freeze_json_value_v1({"bad": object()})  # type: ignore[arg-type]
    with pytest.raises(ContractValidationError, match="NFC"):
        freeze_json_value_v1({"bad": "e\u0301"})


@pytest.mark.parametrize(
    "factory",
    [
        lambda: FrozenJsonArrayV1([1]),  # type: ignore[arg-type]
        lambda: FrozenJsonArrayV1(([],)),  # type: ignore[list-item]
        lambda: FrozenJsonArrayV1(({},)),  # type: ignore[list-item]
        lambda: FrozenJsonObjectV1([("a", 1)]),  # type: ignore[arg-type]
        lambda: FrozenJsonObjectV1((("a", []),)),  # type: ignore[list-item]
        lambda: FrozenJsonObjectV1((("a", 1), ("a", 2))),
        lambda: FrozenJsonObjectV1((("b", 1), ("a", 2))),
        lambda: FrozenJsonObjectV1((("a",),)),  # type: ignore[arg-type]
        lambda: FrozenJsonObjectV1(((1, "value"),)),  # type: ignore[arg-type]
        lambda: FrozenJsonObjectV1((("e\u0301", 1),)),
    ],
)
def test_direct_frozen_json_wrappers_reject_mutable_unsorted_and_malformed_values(
    factory: object,
) -> None:
    with pytest.raises(ContractValidationError):
        factory()  # type: ignore[operator]


def test_canonical_json_sha256_omitting_field_hashes_exact_object_without_mutating() -> None:
    value = {"kind": "example", "selfSha256": "0" * 64, "payload": []}

    assert canonical_json_sha256_omitting_field_v1(
        value, field_name="selfSha256"
    ) == canonical_json_sha256({"kind": "example", "payload": []})
    assert value["selfSha256"] == "0" * 64

    with pytest.raises(ContractValidationError, match="selfSha256"):
        canonical_json_sha256_omitting_field_v1({"kind": "example"}, field_name="selfSha256")
