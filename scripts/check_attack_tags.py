#!/usr/bin/env python3
"""Standalone MITRE ATT&CK tag validation wrapper for Sigma rules."""

from __future__ import annotations

import sys

from validate_rules import find_sigma_rules, load_rule, validate_attack_tags


def main() -> int:
    """Check that every Sigma rule maps to at least one MITRE ATT&CK technique."""
    print("Checking MITRE ATT&CK tags...")
    errors: list[str] = []
    paths = find_sigma_rules()
    if not paths:
        errors.append("No Sigma rule files found under the project rules/ directory")
    for path in paths:
        rule = load_rule(path)
        if rule is None:
            errors.append(f"{path}: could not parse YAML")
            continue
        errors.extend(validate_attack_tags(rule, path))

    if errors:
        print(f"ATT&CK tag validation failed with {len(errors)} error(s):")
        for error in errors:
            print(f"  - {error}")
        return 1

    print("All ATT&CK tag checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
