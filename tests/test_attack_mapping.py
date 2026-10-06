"""Tests for MITRE ATT&CK mapping coverage."""

from validate_rules import find_sigma_rules, load_rule, validate_attack_tags


def test_attack_tags_present() -> None:
    """Every rule maps to at least one MITRE ATT&CK technique tag."""
    failures: list[str] = []
    for path in find_sigma_rules():
        rule = load_rule(path)
        if rule is None:
            continue
        failures.extend(validate_attack_tags(rule, path))
    assert not failures, f"ATT&CK mapping failures: {failures}"


def test_attack_tags_are_strings() -> None:
    """All tags are strings and no empty tags are present."""
    failures: list[str] = []
    for path in find_sigma_rules():
        rule = load_rule(path)
        if rule is None:
            continue
        tags = rule.get("tags", [])
        if not isinstance(tags, list):
            failures.append(f"{path}: 'tags' is not a list")
            continue
        for tag in tags:
            if not isinstance(tag, str) or not tag.strip():
                failures.append(f"{path}: invalid tag value {tag!r}")
    assert not failures, f"Tag value failures: {failures}"
