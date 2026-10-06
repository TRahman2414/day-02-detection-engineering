"""Tests for rule identifier uniqueness and format."""

from pathlib import Path

from validate_rules import (
    detect_duplicate_uuids,
    find_sigma_rules,
    load_rule,
    validate_uuid,
)


def test_uuids_are_valid() -> None:
    """Every rule ID is a valid UUID v4 in canonical lowercase form."""
    failures: list[str] = []
    for path in find_sigma_rules():
        rule = load_rule(path)
        if rule is None:
            continue
        failures.extend(validate_uuid(rule, path))
    assert not failures, f"UUID format failures: {failures}"


def test_uuid_v1_is_not_accepted_as_uuid_v4() -> None:
    """Validation must inspect the stored version bits rather than rewrite them."""
    failures = validate_uuid(
        {"id": "00000000-0000-1000-8000-000000000000"}, Path("synthetic.yml")
    )
    assert failures, "UUID version 1 must not pass the UUID v4 check"


def test_uuids_are_unique() -> None:
    """No two rules share the same identifier."""
    loaded: list[tuple] = []
    for path in find_sigma_rules():
        rule = load_rule(path)
        if rule is None:
            continue
        loaded.append((path, rule))
    failures = detect_duplicate_uuids(loaded)
    assert not failures, f"Duplicate UUID failures: {failures}"
