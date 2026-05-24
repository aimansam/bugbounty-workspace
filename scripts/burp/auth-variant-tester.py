#!/usr/bin/env python3
"""Replay safe auth variants from Burp XML exports without printing secrets."""

from __future__ import annotations

import argparse
import base64
import csv
import json
import re
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from xml.etree import ElementTree


DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
DEFAULT_RESEARCHER = "zx10r8443"
TARGET_PATTERNS = (
    r"/api/v1/users/self$",
    r"/api/v1/users/profile$",
    r"/api/v1/users/find/",
    r"/api/v1/access/.+/account-status",
    r"/Pendo/GetPendoUserData$",
)
DROP_HEADERS = {
    "authorization",
    "cookie",
    "content-length",
    "host",
    "connection",
    "accept-encoding",
}
SAFE_HEADER_ALLOWLIST = {
    "accept",
    "accept-language",
    "content-type",
    "flow",
    "origin",
    "referer",
    "sec-fetch-dest",
    "sec-fetch-mode",
    "sec-fetch-site",
    "x-language",
}
SENSITIVE_RESPONSE_KEYS = {
    "access_token",
    "authorization",
    "cookie",
    "customjwt",
    "email",
    "familyname",
    "givenname",
    "person_xid",
    "personxid",
    "rmsSessionId".lower(),
    "session_id",
    "session_xid",
    "token",
    "xid",
}


@dataclass(frozen=True)
class CapturedRequest:
    source_file: str
    method: str
    url: str
    headers: dict[str, str]
    body: bytes


def decode_element_text(element: ElementTree.Element | None) -> str:
    if element is None or element.text is None:
        return ""
    if element.attrib.get("base64") == "true":
        return base64.b64decode(element.text).decode("utf-8", errors="replace")
    return element.text


def parse_raw_request(raw_request: str, fallback_url: str, source_file: str) -> CapturedRequest | None:
    if "\r\n\r\n" in raw_request:
        head, body = raw_request.split("\r\n\r\n", 1)
    elif "\n\n" in raw_request:
        head, body = raw_request.split("\n\n", 1)
    else:
        head, body = raw_request, ""
    lines = head.splitlines()
    if not lines:
        return None
    parts = lines[0].split()
    if len(parts) < 2:
        return None
    method = parts[0].upper()
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip()] = value.strip()
    return CapturedRequest(source_file, method, fallback_url, headers, body.encode())


def load_captured_requests(paths: list[Path]) -> list[CapturedRequest]:
    captured: list[CapturedRequest] = []
    for path in paths:
        tree = ElementTree.parse(path)
        for item in tree.findall(".//item"):
            url = item.findtext("url") or ""
            raw_request = decode_element_text(item.find("request"))
            parsed = parse_raw_request(raw_request, url, str(path))
            if parsed:
                captured.append(parsed)
    return captured


def is_target(request: CapturedRequest, patterns: list[str]) -> bool:
    parsed = urlparse(request.url)
    target = parsed.path
    if request.method not in {"GET", "POST"}:
        return False
    return any(re.search(pattern, target) for pattern in patterns)


def safe_headers(headers: dict[str, str], user_agent: str, variant: str) -> dict[str, str]:
    output: dict[str, str] = {"User-Agent": user_agent}
    for name, value in headers.items():
        lower = name.lower()
        if lower in DROP_HEADERS:
            continue
        if lower in SAFE_HEADER_ALLOWLIST:
            output[name] = value
    if variant == "invalid-authorization":
        output["Authorization"] = "Bearer invalid"
    return output


def response_shape(body: bytes) -> tuple[list[str], bool]:
    text = body[:300_000].decode("utf-8", errors="replace").strip()
    if not text.startswith(("{", "[")):
        return [], False
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return [], False
    keys = sorted(parsed.keys()) if isinstance(parsed, dict) else []
    lowered = {key.lower() for key in keys}
    sensitive = bool(lowered & SENSITIVE_RESPONSE_KEYS)
    return keys, sensitive


def send_variant(request: CapturedRequest, variant: str, args: argparse.Namespace) -> dict[str, object]:
    headers = safe_headers(request.headers, args.user_agent, variant)
    body = request.body if request.method == "POST" else None
    outbound = Request(request.url, data=body, method=request.method, headers=headers)
    try:
        with urlopen(outbound, timeout=args.timeout, context=ssl.create_default_context()) as response:
            body = response.read(args.max_body_bytes)
            keys, sensitive = response_shape(body)
            return {
                "researcher": args.researcher,
                "source_file": request.source_file,
                "variant": variant,
                "method": request.method,
                "host": urlparse(request.url).netloc,
                "path": urlparse(request.url).path,
                "status": response.status,
                "content_type": response.headers.get("content-type", ""),
                "response_length_sampled": len(body),
                "json_keys": keys,
                "contains_sensitive_key_names": sensitive,
            }
    except HTTPError as error:
        body = error.read(args.max_body_bytes)
        keys, sensitive = response_shape(body)
        return {
            "researcher": args.researcher,
            "source_file": request.source_file,
            "variant": variant,
            "method": request.method,
            "host": urlparse(request.url).netloc,
            "path": urlparse(request.url).path,
            "status": error.code,
            "content_type": error.headers.get("content-type", "") if error.headers else "",
            "response_length_sampled": len(body),
            "json_keys": keys,
            "contains_sensitive_key_names": sensitive,
        }
    except (TimeoutError, URLError, OSError) as error:
        return {
            "researcher": args.researcher,
            "source_file": request.source_file,
            "variant": variant,
            "method": request.method,
            "host": urlparse(request.url).netloc,
            "path": urlparse(request.url).path,
            "error": str(error),
        }


def unique_targets(requests: list[CapturedRequest], patterns: list[str], limit: int) -> list[CapturedRequest]:
    seen: set[tuple[str, str]] = set()
    selected: list[CapturedRequest] = []
    for request in requests:
        if not is_target(request, patterns):
            continue
        key = (request.method, request.url)
        if key in seen:
            continue
        seen.add(key)
        selected.append(request)
        if len(selected) >= limit:
            break
    return selected


def write_results(program: str, results: list[dict[str, object]], selected: list[CapturedRequest], args: argparse.Namespace) -> None:
    out_dir = Path("programs") / program / "recon" / "auth-variant-tests"
    out_dir.mkdir(parents=True, exist_ok=True)
    metadata = {
        "researcher": args.researcher,
        "input_files": args.files,
        "target_count": len(selected),
        "result_count": len(results),
        "variants": args.variant,
        "delay": args.delay,
        "timeout": args.timeout,
        "user_agent": args.user_agent,
    }
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    (out_dir / "results.json").write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")
    with (out_dir / "results.csv").open("w", newline="") as handle:
        fieldnames = ["variant", "method", "host", "path", "status", "content_type", "contains_sensitive_key_names", "json_keys", "error"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            row = {name: result.get(name, "") for name in fieldnames}
            row["json_keys"] = "|".join(result.get("json_keys", [])) if isinstance(result.get("json_keys"), list) else ""
            writer.writerow(row)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Replay safe no-auth/invalid-auth variants for selected Burp requests.")
    parser.add_argument("program", help="Program folder name under programs/")
    parser.add_argument("files", nargs="+", help="Burp XML export files")
    parser.add_argument("--variant", action="append", choices=["no-auth", "invalid-authorization"], default=None, help="Variant to test. Default: both")
    parser.add_argument("--pattern", action="append", default=None, help="Regex path pattern to select. Default: users/self, account-status, Pendo")
    parser.add_argument("--max-targets", type=int, default=10, help="Maximum unique GET targets to test. Default: 10")
    parser.add_argument("--delay", type=float, default=2.0, help="Delay between requests in seconds. Default: 2")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds. Default: 10")
    parser.add_argument("--max-body-bytes", type=int, default=300_000, help="Maximum response bytes sampled. Default: 300000")
    parser.add_argument("--researcher", default=DEFAULT_RESEARCHER, help=f"Researcher username stamp. Default: {DEFAULT_RESEARCHER}")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="HTTP User-Agent header")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    args.variant = args.variant or ["no-auth", "invalid-authorization"]
    patterns = args.pattern or list(TARGET_PATTERNS)
    requests = load_captured_requests([Path(file_name) for file_name in args.files])
    selected = unique_targets(requests, patterns, args.max_targets)
    results: list[dict[str, object]] = []
    for request in selected:
        for variant in args.variant:
            results.append(send_variant(request, variant, args))
            time.sleep(args.delay)
    write_results(args.program, results, selected, args)
    print(f"Selected targets: {len(selected)}")
    print(f"Results: {len(results)}")
    print(f"Output: programs/{args.program}/recon/auth-variant-tests")
    for result in results:
        status = result.get("status", "ERR")
        sensitive = result.get("contains_sensitive_key_names", False)
        print(f"{result['variant']} {result['method']} {result['host']}{result['path']} -> {status} sensitive_keys={sensitive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())