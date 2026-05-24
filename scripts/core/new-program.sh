#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <program-name>" >&2
  exit 1
fi

program_name="$1"
program_dir="programs/${program_name}"

mkdir -p programs
mkdir -p "${program_dir}/recon" "${program_dir}/evidence" "${program_dir}/reports" "${program_dir}/notes" "${program_dir}/scripts/custom"
cp templates/scope.md "${program_dir}/scope.md"
cp templates/fast-hunt-checklist.md "${program_dir}/notes/fast-hunt-checklist.md"
touch "${program_dir}/targets.txt"

printf 'Created %s\n' "${program_dir}"
