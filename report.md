# Build Report

This file records the scope of the original Day 02 project build. For the current rule inventory, review findings, fixes, and validation results, see [`codex-review.md`](codex-review.md).

The project contains ten experimental Sigma detections (six Windows and four Linux), Python validation, pytest checks, Splunk and Elasticsearch Lucene conversion scripts, documentation, and a GitHub Actions workflow. It does not require Docker, virtual machines, a live SIEM, or system-level packages.

## Local commands

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m pytest -v
python scripts/validate_rules.py
python scripts/check_metadata.py
python scripts/check_attack_tags.py
```

Install the pinned Sigma CLI and backends when you want to validate/convert rules:

```bash
pip install -e ".[sigma]"
sigma check --exclude attacktag --fail-on-issues rules/
bash scripts/convert_splunk.sh
bash scripts/convert_elastic.sh
```

The Elastic backend output is Lucene query syntax, not Elasticsearch Query DSL or ES|QL. Conversion is local query generation only; no live Splunk or Elasticsearch deployment has been tested.
