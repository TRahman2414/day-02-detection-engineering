#!/usr/bin/env python3
"""Lightweight Sigma rule validation for the Detection Engineering project.

This script recursively finds Sigma YAML files, validates their structure and
metadata, and reports problems with a non-zero exit code when validation fails.
"""

from __future__ import annotations

import sys
import re
import uuid
from datetime import date
from pathlib import Path
from typing import Any

import yaml

REQUIRED_FIELDS = (
    "title",
    "id",
    "status",
    "description",
    "author",
    "date",
    "logsource",
    "detection",
    "falsepositives",
    "level",
    "tags",
)

VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
VALID_ATTACK_TACTICS = {
    "initial-access", "execution", "persistence", "privilege-escalation",
    "defense-evasion", "credential-access", "discovery", "lateral-movement",
    "collection", "command-and-control", "exfiltration", "impact",
    "reconnaissance", "resource-development",
}
ATTACK_TECHNIQUE_TAG = re.compile(r"attack\.t\d{4}(?:\.\d{3})?\Z")


class UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(loader: UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping", node.start_mark,
                f"duplicate key {key!r}", key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def get_project_root() -> Path:
    """Return the repository root based on this script's location."""
    return Path(__file__).resolve().parent.parent


def find_sigma_rules(root: Path | None = None) -> list[Path]:
    """Recursively find all Sigma rule YAML files under ``root``.

    Sigma rules are expected to live in a ``rules`` directory and use the
    ``.yml`` extension.
    """
    if root is None:
        root = get_project_root()
    rules_dir = root / "rules"
    return sorted(rules_dir.rglob("*.yml"))


def load_rule(path: Path) -> dict[str, Any] | None:
    """Parse a Sigma rule YAML file.

    Returns ``None`` when the file cannot be parsed. The caller is responsible
    for reporting the parse error.
    """
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.load(handle, Loader=UniqueKeyLoader)
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None
    return data


def validate_uuid(rule: dict[str, Any], path: Path) -> list[str]:
    """Verify that the rule ``id`` is a valid UUID v4 string."""
    errors: list[str] = []
    rule_id = rule.get("id")
    if not rule_id:
        errors.append(f"{path}: missing 'id' field")
        return errors
    try:
        parsed = uuid.UUID(str(rule_id))
        if parsed.version != 4:
            errors.append(f"{path}: 'id' is not a UUID v4")
        if str(parsed) != str(rule_id).lower():
            errors.append(f"{path}: 'id' is not a canonical lowercase UUID")
    except ValueError:
        errors.append(f"{path}: 'id' value '{rule_id}' is not a valid UUID v4")
    return errors


def validate_required_metadata(rule: dict[str, Any], path: Path) -> list[str]:
    """Verify that all required top-level metadata fields are present."""
    errors: list[str] = []
    for field in REQUIRED_FIELDS:
        if field not in rule or rule[field] is None:
            errors.append(f"{path}: missing required field '{field}'")
    for field in ("title", "status", "description", "author"):
        value = rule.get(field)
        if not isinstance(value, str) or not value.strip():
            errors.append(f"{path}: '{field}' must be a non-empty string")
    rule_date = rule.get("date")
    if isinstance(rule_date, date):
        pass
    elif isinstance(rule_date, str):
        try:
            date.fromisoformat(rule_date)
        except ValueError:
            errors.append(f"{path}: 'date' must be an ISO YYYY-MM-DD date")
    else:
        errors.append(f"{path}: 'date' must be an ISO YYYY-MM-DD date")
    for field in ("logsource", "detection"):
        value = rule.get(field)
        if not isinstance(value, dict) or not value:
            errors.append(f"{path}: '{field}' must be a non-empty mapping")
    return errors


def validate_attack_tags(rule: dict[str, Any], path: Path) -> list[str]:
    """Verify that the rule contains at least one MITRE ATT&CK technique tag."""
    errors: list[str] = []
    tags = rule.get("tags", [])
    if not isinstance(tags, list) or not tags:
        errors.append(f"{path}: 'tags' must be a non-empty list")
        return errors

    has_technique = any(isinstance(tag, str) and ATTACK_TECHNIQUE_TAG.fullmatch(tag) for tag in tags)
    if not has_technique:
        errors.append(f"{path}: no well-formed MITRE ATT&CK technique tag found")
    for tag in tags:
        if isinstance(tag, str) and tag.startswith("attack."):
            suffix = tag.removeprefix("attack.")
            if suffix.startswith("t"):
                if not ATTACK_TECHNIQUE_TAG.fullmatch(tag):
                    errors.append(f"{path}: malformed ATT&CK technique tag {tag!r}")
            elif suffix not in VALID_ATTACK_TACTICS:
                errors.append(f"{path}: unknown or malformed ATT&CK tactic tag {tag!r}")
    return errors


def validate_falsepositives(rule: dict[str, Any], path: Path) -> list[str]:
    """Verify that false-positive guidance is provided and non-empty."""
    errors: list[str] = []
    falsepositives = rule.get("falsepositives")
    if not isinstance(falsepositives, list) or not falsepositives:
        errors.append(f"{path}: 'falsepositives' must be a non-empty list")
    elif any(not isinstance(item, str) or not item.strip() or item.strip().lower() == "unknown" for item in falsepositives):
        errors.append(f"{path}: 'falsepositives' must contain useful, non-empty descriptions")
    return errors


def validate_level(rule: dict[str, Any], path: Path) -> list[str]:
    """Verify that severity level is one of the allowed values."""
    errors: list[str] = []
    level = rule.get("level")
    if level not in VALID_LEVELS:
        errors.append(f"{path}: 'level' must be one of {sorted(VALID_LEVELS)}, got {level!r}")
    return errors


def detect_duplicate_uuids(rules: list[tuple[Path, dict[str, Any]]]) -> list[str]:
    """Report any duplicate rule IDs across the rule set."""
    errors: list[str] = []
    seen: dict[str, Path] = {}
    for path, rule in rules:
        rule_id = str(rule.get("id", "")).lower()
        if not rule_id:
            continue
        if rule_id in seen:
            errors.append(
                f"duplicate UUID {rule_id} found in {seen[rule_id]} and {path}"
            )
        else:
            seen[rule_id] = path
    return errors


def validate_rule(path: Path, rule: dict[str, Any]) -> list[str]:
    """Run all per-rule validation checks and return collected errors."""
    errors: list[str] = []
    errors.extend(validate_required_metadata(rule, path))
    errors.extend(validate_uuid(rule, path))
    errors.extend(validate_attack_tags(rule, path))
    errors.extend(validate_falsepositives(rule, path))
    errors.extend(validate_level(rule, path))
    condition = rule.get("detection", {}).get("condition") if isinstance(rule.get("detection"), dict) else None
    if not isinstance(condition, str) or not condition.strip():
        errors.append(f"{path}: detection 'condition' must be a non-empty string")
    return errors


def run_all_validations(root: Path | None = None) -> tuple[list[str], list[Path]]:
    """Run the full validation suite.

    Returns a tuple of ``(errors, rule_paths)``. ``errors`` is a flat list of
    human-readable problem descriptions. ``rule_paths`` contains every rule
    file that was successfully loaded.
    """
    if root is None:
        root = get_project_root()

    errors: list[str] = []
    rule_paths = find_sigma_rules(root)
    loaded_rules: list[tuple[Path, dict[str, Any]]] = []

    if not rule_paths:
        errors.append(f"No Sigma rule files found under {root / 'rules'}")
        return errors, []

    for path in rule_paths:
        rule = load_rule(path)
        if rule is None:
            errors.append(f"{path}: could not parse YAML")
            continue
        loaded_rules.append((path, rule))
        errors.extend(validate_rule(path, rule))

    errors.extend(detect_duplicate_uuids(loaded_rules))
    return errors, [path for path, _ in loaded_rules]


def main() -> int:
    """CLI entry point for the validation script."""
    print("=" * 60)
    print("Sigma Rule Validation")
    print("=" * 60)

    errors, rule_paths = run_all_validations()

    print(f"Rules checked: {len(rule_paths)}")
    if errors:
        print(f"Validation failed with {len(errors)} error(s):")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("All rules passed validation.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
