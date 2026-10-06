"""Tests for Sigma rule metadata quality."""

from validate_rules import (
    find_sigma_rules,
    load_rule,
    validate_falsepositives,
    validate_level,
    validate_required_metadata,
)


def test_metadata_fields_present() -> None:
    """All required metadata fields are populated in every rule."""
    failures: list[str] = []
    for path in find_sigma_rules():
        rule = load_rule(path)
        if rule is None:
            continue
        failures.extend(validate_required_metadata(rule, path))
    assert not failures, f"Metadata failures: {failures}"


def test_falsepositives_exist() -> None:
    """Every rule documents at least one realistic false-positive scenario."""
    failures: list[str] = []
    for path in find_sigma_rules():
        rule = load_rule(path)
        if rule is None:
            continue
        failures.extend(validate_falsepositives(rule, path))
    assert not failures, f"False-positive failures: {failures}"


def test_false_positive_documentation_covers_all_rules() -> None:
    """The human-readable false-positive guide must cover every real rule."""
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    documentation = (root / "docs" / "false-positive-analysis.md").read_text(encoding="utf-8")
    missing: list[str] = []
    for path in find_sigma_rules():
        rule = load_rule(path)
        if rule is not None and rule.get("title") not in documentation:
            missing.append(f"{path}: no false-positive guide section for {rule.get('title')!r}")
    assert not missing, f"False-positive documentation gaps: {missing}"


def test_valid_severity_values() -> None:
    """Severity levels are drawn from the Sigma standard set."""
    failures: list[str] = []
    for path in find_sigma_rules():
        rule = load_rule(path)
        if rule is None:
            continue
        failures.extend(validate_level(rule, path))
    assert not failures, f"Severity failures: {failures}"
