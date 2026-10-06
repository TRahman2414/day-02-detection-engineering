"""Tests that every Sigma rule can be parsed and follows the base schema."""

from validate_rules import find_sigma_rules, load_rule


def test_all_rules_parse() -> None:
    """Every Sigma rule file must be valid YAML and parse to a dictionary."""
    failures: list[str] = []
    for path in find_sigma_rules():
        rule = load_rule(path)
        if rule is None:
            failures.append(str(path))
    assert not failures, f"YAML parse failures: {failures}"


def test_expected_rule_inventory_is_present() -> None:
    """Guard against validators passing when rules are accidentally missing."""
    paths = find_sigma_rules()
    assert len(paths) == 10, f"Expected 10 real rule files, found {len(paths)}: {paths}"


def test_required_metadata_exists() -> None:
    """Every rule must contain the top-level fields required by this project."""
    from validate_rules import validate_required_metadata

    failures: list[str] = []
    for path in find_sigma_rules():
        rule = load_rule(path)
        if rule is None:
            continue
        failures.extend(validate_required_metadata(rule, path))
    assert not failures, f"Metadata validation failures: {failures}"


def test_logsource_exists() -> None:
    """Every rule must define a logsource section."""
    failures: list[str] = []
    for path in find_sigma_rules():
        rule = load_rule(path)
        if rule is None:
            continue
        logsource = rule.get("logsource")
        if not isinstance(logsource, dict) or not logsource:
            failures.append(f"{path}: missing or empty 'logsource'")
    assert not failures, f"Logsource failures: {failures}"


def test_detection_exists() -> None:
    """Every rule must define a detection section."""
    failures: list[str] = []
    for path in find_sigma_rules():
        rule = load_rule(path)
        if rule is None:
            continue
        detection = rule.get("detection")
        if not isinstance(detection, dict) or not detection:
            failures.append(f"{path}: missing or empty 'detection'")
    assert not failures, f"Detection failures: {failures}"


def test_conditions_are_present() -> None:
    """Every actual rule must provide a non-empty Sigma condition."""
    failures: list[str] = []
    for path in find_sigma_rules():
        rule = load_rule(path)
        if rule is None:
            continue
        detection = rule.get("detection")
        if not isinstance(detection, dict) or not isinstance(detection.get("condition"), str) or not detection["condition"].strip():
            failures.append(f"{path}: missing or empty detection.condition")
    assert not failures, f"Condition failures: {failures}"


def test_duplicate_yaml_keys_are_rejected(tmp_path) -> None:
    """Duplicate YAML keys must not silently override detection content."""
    rule_path = tmp_path / "duplicate.yml"
    rule_path.write_text("title: first\ntitle: second\n", encoding="utf-8")
    assert load_rule(rule_path) is None
