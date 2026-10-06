#!/usr/bin/env bash
# Convert local Sigma rules to Splunk SPL and write them to output/splunk/.
# This script does not require a running Splunk instance; it only generates
# compatible queries using the pySigma Splunk backend.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
RULES_DIR="${PROJECT_ROOT}/rules"
OUTPUT_DIR="${PROJECT_ROOT}/output/splunk"

echo "==> Splunk conversion started"

if [[ -n "${SIGMA_BIN:-}" ]]; then
    SIGMA_COMMAND=("${SIGMA_BIN}")
elif command -v sigma >/dev/null 2>&1; then
    SIGMA_COMMAND=("$(command -v sigma)")
elif [[ -x "${PROJECT_ROOT}/.venv/bin/sigma" ]]; then
    SIGMA_COMMAND=("${PROJECT_ROOT}/.venv/bin/sigma")
else
    echo "ERROR: 'sigma' command not found."
    echo "Install the Sigma CLI and the Splunk backend, for example:"
    echo "  pip install sigma-cli pysigma-backend-splunk"
    exit 1
fi

if ! "${SIGMA_COMMAND[@]}" plugin list 2>/dev/null | grep -qi splunk; then
    echo "ERROR: pySigma Splunk backend plugin is not installed."
    echo "Install it with:"
    echo "  pip install pysigma-backend-splunk"
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"
TEMP_DIR="$(mktemp -d "${OUTPUT_DIR}/.convert.XXXXXX")"
trap 'rm -rf -- "${TEMP_DIR}"' EXIT

echo "==> Converting rules to Splunk SPL..."

# Convert each rule into a separate SPL file using the default text format.
# The --without-pipeline flag is used for the base build so no backend-specific
# processing pipeline configuration is required.
"${SIGMA_COMMAND[@]}" convert \
    --target splunk \
    --format default \
    --without-pipeline \
    --output-dir "${TEMP_DIR}" \
    "${RULES_DIR}"

expected_count="$(find "${RULES_DIR}" -type f -name '*.yml' | wc -l)"
actual_count="$(find "${TEMP_DIR}" -maxdepth 1 -type f -name '*.txt' | wc -l)"
if [[ "${actual_count}" -ne "${expected_count}" ]]; then
    echo "ERROR: expected ${expected_count} converted rule files, found ${actual_count}." >&2
    exit 1
fi
while IFS= read -r rule_path; do
    query_name="$(basename "${rule_path}" .yml).txt"
    if [[ ! -f "${TEMP_DIR}/${query_name}" ]]; then
        echo "ERROR: conversion did not create ${query_name}." >&2
        exit 1
    fi
done < <(find "${RULES_DIR}" -type f -name '*.yml' -print)
cp -- "${TEMP_DIR}"/*.txt "${OUTPUT_DIR}/"

echo "==> Generated ${actual_count} Splunk SPL query files in: ${OUTPUT_DIR}"
ls -1 "${OUTPUT_DIR}"
