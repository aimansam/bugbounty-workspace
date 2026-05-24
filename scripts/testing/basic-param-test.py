#!/usr/bin/env python3
"""Basic, rate-limited query parameter tests from param-crawler output."""

from __future__ import annotations

import argparse
import csv
import json
import time
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen


DEFAULT_RESEARCHER = "zx10r8443"
DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
DEFAULT_MARKER = "zx10r8443-param-check"
INTERESTING_NAMES = {
    "redirect",
    "redirecturl",
    "return",
    "returnurl",
    "callback",
    "callbackurl",
    "continue",
    "next",
    "url",
    "uri",
    "target",
    "dest",
    "destination",
    "id",
    "userid",
    "accountid",
    "courseid",
    "role",
    "token",
    "code",
    "state",
    "email",
    "searchquery",
    "q",
    "query",
}


def load_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip().lower() for line in path.read_text().splitlines() if line.strip() and not line.startswith("#")]


def normalize_host(host: str) -> str:
    return host.lower().strip().lstrip("*.")


def is_allowed_host(host: str, allowed_roots: set[str], blocked_hosts: set[str]) -> bool:
    clean_host = host.lower().split(":", 1)[0]
    if clean_host in blocked_hosts:
        return False
    return any(clean_host == root or clean_host.endswith(f".{root}") for root in allowed_roots)


def fetch(url: str, timeout: int, user_agent: str) -> tuple[int, str, bytes]:
    request = Request(url, headers={"User-Agent": user_agent, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1"})
    try:
        with urlopen(request, timeout=timeout) as response:
            content_type = response.headers.get("content-type", "").lower()
            return response.status, content_type, response.read(500_000)
    except HTTPError as error:
        content_type = error.headers.get("content-type", "").lower() if error.headers else ""
        return error.code, content_type, error.read(200_000)


def load_params(path: Path) -> list[tuple[str, str]]:
    rows: list[tuple[str, str]] = []
    with path.open(newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            url = (row.get("url") or "").strip()
            param = (row.get("parameter") or "").strip()
            if url and param:
                rows.append((url, param))
    return rows


def build_test_url(url: str, param: str, marker: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    updated = [(name, marker if name == param else value) for name, value in pairs]
    if not any(name == param for name, _ in updated):
        updated.append((param, marker))
    return urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))


def select_params(rows: list[tuple[str, str]], interesting_only: bool) -> list[tuple[str, str]]:
    unique = sorted(set(rows), key=lambda item: (item[1].lower() not in INTERESTING_NAMES, item[0], item[1]))
    if not interesting_only:
        return unique
    return [(url, param) for url, param in unique if param.lower() in INTERESTING_NAMES]


def run_tests(args: argparse.Namespace) -> list[dict[str, str | int | bool]]:
    program_dir = Path("programs") / args.program
    input_path = Path(args.input) if args.input else program_dir / "recon" / "param-crawler" / "query-params.csv"
    out_dir = program_dir / "recon" / "basic-param-test"
    out_dir.mkdir(parents=True, exist_ok=True)

    allowed_roots = {normalize_host(target) for target in load_lines(program_dir / "targets.txt")}
    blocked_hosts = set(load_lines(program_dir / "out-of-scope.txt"))
    selected = select_params(load_params(input_path), args.interesting_only)
    results: list[dict[str, str | int | bool]] = []

    for url, param in selected[: args.max_tests]:
        host = urlparse(url).netloc
        if not is_allowed_host(host, allowed_roots, blocked_hosts):
            continue
        test_url = build_test_url(url, param, args.marker)
        try:
            status, content_type, body = fetch(test_url, args.timeout, args.user_agent)
            reflected = args.marker.encode() in body
            results.append({
                "researcher": args.researcher,
                "url": url,
                "param": param,
                "test_url": test_url,
                "status": status,
                "content_type": content_type,
                "marker_reflected": reflected,
            })
        except (TimeoutError, URLError, OSError) as error:
            results.append({
                "researcher": args.researcher,
                "url": url,
                "param": param,
                "test_url": test_url,
                "error": str(error),
            })
        time.sleep(args.delay)

    metadata = {
        "researcher": args.researcher,
        "program": args.program,
        "input": str(input_path),
        "max_tests": args.max_tests,
        "delay": args.delay,
        "timeout": args.timeout,
        "interesting_only": args.interesting_only,
        "marker": args.marker,
        "user_agent": args.user_agent,
        "tested": len(results),
        "reflections": sum(1 for result in results if result.get("marker_reflected") is True),
    }
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    (out_dir / "results.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run basic, low-rate GET parameter reflection checks.")
    parser.add_argument("program", help="Program folder name under programs/")
    parser.add_argument("--input", help="Path to query-params.csv. Defaults to the program param-crawler output.")
    parser.add_argument("--max-tests", type=int, default=10, help="Maximum parameters to test. Default: 10")
    parser.add_argument("--delay", type=float, default=2.0, help="Delay between requests in seconds. Default: 2.0")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds. Default: 10")
    parser.add_argument("--interesting-only", action="store_true", help="Only test parameter names commonly tied to redirects, IDs, tokens, search, or account flows.")
    parser.add_argument("--marker", default=DEFAULT_MARKER, help=f"Reflection marker. Default: {DEFAULT_MARKER}")
    parser.add_argument("--researcher", default=DEFAULT_RESEARCHER, help=f"Researcher username stamp. Default: {DEFAULT_RESEARCHER}")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="HTTP User-Agent header. Defaults to a Linux Chrome User-Agent string.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    results = run_tests(args)
    reflections = sum(1 for result in results if result.get("marker_reflected") is True)
    print(f"Researcher: {args.researcher}")
    print(f"Tested parameters: {len(results)}")
    print(f"Reflections: {reflections}")
    print(f"Output: programs/{args.program}/recon/basic-param-test")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())