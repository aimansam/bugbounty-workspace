#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <program-name>" >&2
  exit 1
fi

program_name="$1"
program_dir="programs/${program_name}"
targets_file="${program_dir}/targets.txt"
out_dir="${program_dir}/recon"

if [[ ! -f "${targets_file}" ]]; then
  echo "Missing ${targets_file}. Create a program with scripts/core/new-program.sh first." >&2
  exit 1
fi

mkdir -p "${out_dir}"

while IFS= read -r target; do
  [[ -z "${target}" || "${target}" =~ ^# ]] && continue
  safe_name="${target//[^A-Za-z0-9._-]/_}"
  {
    echo "# ${target}"
    echo
    echo "## DNS"
    dig "${target}" A +short || true
    echo
    echo "## HTTP Headers"
    curl -I --max-time 10 --silent --show-error "https://${target}" || true
  } > "${out_dir}/${safe_name}.txt"
done < "${targets_file}"

printf 'Saved passive recon to %s\n' "${out_dir}"
