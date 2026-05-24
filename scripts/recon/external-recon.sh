#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <program-name>" >&2
  exit 1
fi

program_name="$1"
program_dir="programs/${program_name}"
targets_file="${program_dir}/targets.txt"
out_dir="${program_dir}/recon/external-recon"
max_roots="${BB_MAX_ROOTS:-2}"
tool_timeout="${BB_TOOL_TIMEOUT:-90s}"

if [[ ! -f "${targets_file}" ]]; then
  echo "Missing ${targets_file}. Create a program with scripts/core/new-program.sh first." >&2
  exit 1
fi

mkdir -p "${out_dir}"
: > "${out_dir}/commands.log"
: > "${out_dir}/missing-tools.txt"
: > "${out_dir}/root-targets.txt"
: > "${out_dir}/subdomains.txt"
: > "${out_dir}/live-hosts.txt"
: > "${out_dir}/urls.txt"
: > "${out_dir}/metadata.txt"

log_run() {
  printf '$ %s\n' "$*" >> "${out_dir}/commands.log"
}

run_limited() {
  if command -v timeout >/dev/null 2>&1; then
    timeout "${tool_timeout}" "$@"
  else
    "$@"
  fi
}

need_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '%s\n' "$1" >> "${out_dir}/missing-tools.txt"
    return 1
  fi
  return 0
}

need_projectdiscovery_httpx() {
  if ! need_tool httpx; then
    return 1
  fi
  if ! httpx -h 2>&1 | grep -q -- '-silent'; then
    printf '%s\n' "httpx-projectdiscovery" >> "${out_dir}/missing-tools.txt"
    return 1
  fi
  return 0
}

clean_target() {
  local target="$1"
  target="${target#http://}"
  target="${target#https://}"
  target="${target%%/*}"
  target="${target#*.}"
  printf '%s\n' "$target"
}

processed_roots=0
while IFS= read -r raw_target; do
  [[ -z "${raw_target}" || "${raw_target}" =~ ^# ]] && continue
  if (( processed_roots >= max_roots )); then
    break
  fi
  target="$(clean_target "${raw_target}")"
  [[ -z "${target}" ]] && continue
  processed_roots=$((processed_roots + 1))
  printf '%s\n' "${target}" >> "${out_dir}/root-targets.txt"

  if need_tool subfinder; then
    log_run subfinder -silent -d "${target}"
    run_limited subfinder -silent -d "${target}" >> "${out_dir}/subdomains.txt" || true
  fi

  if need_tool waybackurls; then
    log_run waybackurls "${target}"
    printf '%s\n' "${target}" | run_limited waybackurls >> "${out_dir}/urls.txt" || true
  fi

done < "${targets_file}"

sort -u "${out_dir}/subdomains.txt" -o "${out_dir}/subdomains.txt"
sort -u "${out_dir}/urls.txt" -o "${out_dir}/urls.txt"

if [[ -s "${out_dir}/subdomains.txt" ]] && need_projectdiscovery_httpx; then
  log_run httpx -silent -follow-redirects -status-code -title -tech-detect -l "${out_dir}/subdomains.txt"
  run_limited httpx -silent -follow-redirects -status-code -title -tech-detect -l "${out_dir}/subdomains.txt" > "${out_dir}/live-hosts.txt" || true
fi

if [[ -s "${out_dir}/live-hosts.txt" ]] && need_tool katana; then
  cut -d ' ' -f 1 "${out_dir}/live-hosts.txt" | grep -E '^https?://' | sort -u > "${out_dir}/katana-input.txt"
  if [[ -s "${out_dir}/katana-input.txt" ]]; then
    log_run katana -silent -d 2 -list "${out_dir}/katana-input.txt"
    run_limited katana -silent -d 2 -list "${out_dir}/katana-input.txt" >> "${out_dir}/urls.txt" || true
    sort -u "${out_dir}/urls.txt" -o "${out_dir}/urls.txt"
  fi
fi

{
  printf 'program=%s\n' "${program_name}"
  printf 'max_roots=%s\n' "${max_roots}"
  printf 'tool_timeout=%s\n' "${tool_timeout}"
  printf 'root_targets=%s\n' "$(sort -u "${out_dir}/root-targets.txt" 2>/dev/null | wc -l)"
  printf 'subdomains=%s\n' "$(wc -l < "${out_dir}/subdomains.txt")"
  printf 'live_hosts=%s\n' "$(wc -l < "${out_dir}/live-hosts.txt")"
  printf 'urls=%s\n' "$(wc -l < "${out_dir}/urls.txt")"
  printf 'missing_tools=%s\n' "$(sort -u "${out_dir}/missing-tools.txt" | tr '\n' ',' | sed 's/,$//')"
} > "${out_dir}/metadata.txt"

printf 'Saved external recon to %s\n' "${out_dir}"
if [[ -s "${out_dir}/missing-tools.txt" ]]; then
  printf 'Missing optional tools: %s\n' "$(sort -u "${out_dir}/missing-tools.txt" | tr '\n' ' ')"
fi
