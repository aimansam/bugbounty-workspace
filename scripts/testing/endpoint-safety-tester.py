#!/usr/bin/env python3
"""Lightweight endpoint checks for authorized bug bounty testing.

The script is intentionally conservative: it sends a small number of payloads,
does not fuzz aggressively, and records response metadata/snippets instead of
full bodies or secrets.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
from urllib.request import Request, urlopen


DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
DEFAULT_RESEARCHER = "zx10r8443"

SQLI_PAYLOADS = ("'", "\"", "')", "'--", "' OR '1'='2")
COMMAND_PAYLOADS = (";id", "|id", "`id`", "$(id)")
TRAVERSAL_PAYLOADS = ("../", "../../", "..%2f..%2f", "%2e%2e%2f")

SQLI_PATTERNS = (
    r"sql syntax",
    r"mysql",
    r"mariadb",
    r"postgresql",
    r"oracle error",
    r"sqlite",
    r"odbc",
    r"unterminated quoted string",
    r"syntax error at or near",
)
COMMAND_PATTERNS = (
    r"uid=\d+\(",
    r"gid=\d+\(",
    r"sh: .*not found",
    r"/bin/(?:sh|bash)",
    r"command not found",
)
TRAVERSAL_PATTERNS = (
    r"root:x:0:0",
    r"\[boot loader\]",
    r"No such file or directory",
    r"Access to the path",
)
SENSITIVE_RE = re.compile(
    r"(Bearer\s+[A-Za-z0-9._-]+|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"
)


@dataclass(frozen=True)
class Target:
    method: str
    url: str


def read_targets(path: Path) -> list[Target]:
    targets: list[Target] = []
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(maxsplit=1)
        if len(parts) == 2 and parts[0].upper() in {"GET", "POST"}:
            targets.append(Target(parts[0].upper(), parts[1]))
        else:
            targets.append(Target("GET", line))
    return targets


def mutate_query(url: str, parameter: str, payload: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    mutated = [(key, payload if key == parameter else value) for key, value in pairs]
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(mutated), parsed.fragment))


def query_parameters(url: str) -> list[str]:
    return [key for key, _ in parse_qsl(urlparse(url).query, keep_blank_values=True)]


def redact(text: str) -> str:
    return SENSITIVE_RE.sub("[REDACTED]", text)


def body_fingerprint(body: bytes) -> str:
    return hashlib.sha256(body[:50_000]).hexdigest()[:16]


def send(method: str, url: str, args: argparse.Namespace) -> dict[str, object]:
    headers = {
        "User-Agent": args.user_agent,
        "Accept": "text/html,application/json,text/plain,*/*",
    }
    if args.header:
        for header in args.header:
            if ":" not in header:
                continue
            name, value = header.split(":", 1)
            headers[name.strip()] = value.strip()
    request = Request(url, method=method, headers=headers)
    try:
        with urlopen(request, timeout=args.timeout, context=ssl.create_default_context()) as response:
            body = response.read(args.max_body_bytes)
            return response_metadata(response.status, response.headers.get("content-type", ""), body)
    except HTTPError as error:
        body = error.read(args.max_body_bytes)
        return response_metadata(error.code, error.headers.get("content-type", "") if error.headers else "", body)
    except (TimeoutError, URLError, OSError) as error:
        return {"error": str(error)}


def response_metadata(status: int, content_type: str, body: bytes) -> dict[str, object]:
    text = body.decode("utf-8", errors="replace")
    snippet = redact(re.sub(r"\s+", " ", text[:600])).strip()
    lowered = text.lower()
    return {
        "status": status,
        "content_type": content_type,
        "length": len(body),
        "fingerprint": body_fingerprint(body),
        "snippet": snippet,
        "sqli_signal": any(re.search(pattern, lowered, re.I) for pattern in SQLI_PATTERNS),
        "command_signal": any(re.search(pattern, text, re.I) for pattern in COMMAND_PATTERNS),
        "traversal_signal": any(re.search(pattern, text, re.I) for pattern in TRAVERSAL_PATTERNS),
    }


def run_checks(target: Target, args: argparse.Namespace) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    params = query_parameters(target.url)
    baseline = send(target.method, target.url, args)
    rows.append(make_row(target, "baseline", "", "", baseline))
    if not params:
        return rows
    payload_groups = []
    if "sqli" in args.check:
        payload_groups.append(("sqli", SQLI_PAYLOADS))
    if "cmd" in args.check:
        payload_groups.append(("cmd", COMMAND_PAYLOADS))
    if "traversal" in args.check:
        payload_groups.append(("traversal", TRAVERSAL_PAYLOADS))
    for parameter in params[: args.max_params_per_url]:
        for check_name, payloads in payload_groups:
            for payload in payloads[: args.max_payloads_per_check]:
                mutated_url = mutate_query(target.url, parameter, payload)
                result = send(target.method, mutated_url, args)
                rows.append(make_row(target, check_name, parameter, payload, result))
                time.sleep(args.delay)
    return rows


def make_row(target: Target, check: str, parameter: str, payload: str, result: dict[str, object]) -> dict[str, object]:
    parsed = urlparse(target.url)
    return {
        "method": target.method,
        "host": parsed.netloc,
        "path": parsed.path,
        "check": check,
        "parameter": parameter,
        "payload": payload,
        "status": result.get("status", ""),
        "length": result.get("length", ""),
        "fingerprint": result.get("fingerprint", ""),
        "sqli_signal": result.get("sqli_signal", False),
        "command_signal": result.get("command_signal", False),
        "traversal_signal": result.get("traversal_signal", False),
        "error": result.get("error", ""),
        "snippet": result.get("snippet", ""),
    }


def write_outputs(rows: list[dict[str, object]], args: argparse.Namespace) -> Path:
    out_dir = Path("programs") / args.program / "recon" / "endpoint-safety-tests"
    out_dir.mkdir(parents=True, exist_ok=True)
    metadata = {
        "researcher": args.researcher,
        "target_file": str(args.targets),
        "checks": args.check,
        "delay": args.delay,
        "note": "Conservative metadata-only testing. Review signals manually before reporting.",
    }
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    (out_dir / "results.json").write_text(json.dumps(rows, indent=2, sort_keys=True) + "\n")
    with (out_dir / "results.csv").open("w", newline="") as handle:
        fieldnames = ["method", "host", "path", "check", "parameter", "payload", "status", "length", "fingerprint", "sqli_signal", "command_signal", "traversal_signal", "error", "snippet"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    return out_dir


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Conservative endpoint safety tester for authorized programs.")
    parser.add_argument("program", help="Program folder name under programs/")
    parser.add_argument("targets", type=Path, help="Text file with one URL per line, optionally prefixed by GET/POST")
    parser.add_argument("--check", action="append", choices=["sqli", "cmd", "traversal"], default=None, help="Checks to run. Default: all")
    parser.add_argument("--header", action="append", default=None, help="Optional header, e.g. 'Authorization: Bearer ...'. Avoid sharing output with secrets.")
    parser.add_argument("--delay", type=float, default=1.5, help="Delay between requests. Default: 1.5")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout seconds. Default: 10")
    parser.add_argument("--max-body-bytes", type=int, default=120_000, help="Response bytes sampled. Default: 120000")
    parser.add_argument("--max-params-per-url", type=int, default=4, help="Max query parameters tested per URL. Default: 4")
    parser.add_argument("--max-payloads-per-check", type=int, default=3, help="Max payloads per check. Default: 3")
    parser.add_argument("--researcher", default=DEFAULT_RESEARCHER)
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.check = args.check or ["sqli", "cmd", "traversal"]
    targets = read_targets(args.targets)
    rows: list[dict[str, object]] = []
    for target in targets:
        rows.extend(run_checks(target, args))
        time.sleep(args.delay)
    out_dir = write_outputs(rows, args)
    print(f"Targets: {len(targets)}")
    print(f"Results: {len(rows)}")
    print(f"Output: {out_dir}")
    for row in rows:
        if row["sqli_signal"] or row["command_signal"] or row["traversal_signal"] or row["error"]:
            print(f"signal {row['check']} {row['host']}{row['path']} param={row['parameter']} status={row['status']} sqli={row['sqli_signal']} cmd={row['command_signal']} traversal={row['traversal_signal']} error={row['error']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())