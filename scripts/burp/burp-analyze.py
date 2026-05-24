#!/usr/bin/env python3
"""Summarize Burp XML exports with light redaction."""

from __future__ import annotations

import argparse
import base64
import csv
import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlparse
from xml.etree import ElementTree


SENSITIVE_NAMES = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-csrf-token",
    "x-xsrf-token",
    "csrf",
    "token",
    "access_token",
    "api-key",
    "apikey",
    "captcha",
    "id_token",
    "ip",
    "ip_address",
    "ipaddress",
    "refresh_token",
    "password",
    "passwd",
    "phone",
    "phonecode",
    "secret",
    "email",
    "username",
    "user",
    "x-api-key",
    "x-forwarded-for",
}
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PERSON_URN_RE = re.compile(r"urn:[^\s/?&\"']+")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")


def decode_element_text(element: ElementTree.Element | None) -> str:
    if element is None or element.text is None:
        return ""
    text = element.text
    if element.attrib.get("base64") == "true":
        return base64.b64decode(text).decode("utf-8", errors="replace")
    return text


def redact_name_value(name: str, value: str) -> str:
    if name.lower() in SENSITIVE_NAMES or any(item in name.lower() for item in ("token", "password", "secret")):
        return "[REDACTED]"
    if len(value) > 120:
        return f"{value[:80]}...[truncated:{len(value)}]"
    return value


def redact_text(value: str) -> str:
    value = EMAIL_RE.sub("[REDACTED_EMAIL]", value)
    value = IPV4_RE.sub("[REDACTED_IP]", value)
    value = PERSON_URN_RE.sub("[REDACTED_PERSON_URN]", value)
    value = JWT_RE.sub("[REDACTED_JWT]", value)
    return value


def parse_headers(raw_message: str) -> tuple[str, dict[str, str]]:
    head = raw_message.split("\r\n\r\n", 1)[0]
    lines = head.splitlines()
    start_line = lines[0] if lines else ""
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        headers[name.strip()] = redact_name_value(name.strip(), value.strip())
    return start_line, headers


def message_body(raw_message: str) -> str:
    if "\r\n\r\n" in raw_message:
        return raw_message.split("\r\n\r\n", 1)[1]
    if "\n\n" in raw_message:
        return raw_message.split("\n\n", 1)[1]
    return ""


def redact_json(value: object) -> object:
    if isinstance(value, dict):
        redacted: dict[str, object] = {}
        for key, child in value.items():
            key_lower = key.lower()
            if key_lower in SENSITIVE_NAMES or any(item in key_lower for item in ("token", "password", "secret", "jwt", "captcha", "phone", "api_key", "apikey")):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact_json(child)
        return redacted
    if isinstance(value, list):
        return [redact_json(item) for item in value]
    if isinstance(value, str):
        value = redact_text(value)
        if len(value) > 120:
            return f"{value[:80]}...[truncated:{len(value)}]"
    return value


def parse_json_body(raw_message: str) -> object:
    body = message_body(raw_message).strip()
    if not body or not body.startswith(("{", "[")):
        return None
    try:
        return redact_json(json.loads(body))
    except json.JSONDecodeError:
        return None


def query_params(url: str) -> dict[str, str]:
    parsed = urlparse(url)
    return {name: redact_name_value(name, value) for name, value in parse_qsl(parsed.query, keep_blank_values=True)}


def analyze_file(path: Path) -> list[dict[str, object]]:
    tree = ElementTree.parse(path)
    summaries: list[dict[str, object]] = []
    for index, item in enumerate(tree.findall(".//item"), start=1):
        url = item.findtext("url") or ""
        request = decode_element_text(item.find("request"))
        response = decode_element_text(item.find("response"))
        request_line, request_headers = parse_headers(request)
        response_line, response_headers = parse_headers(response)
        summaries.append({
            "file": str(path),
            "index": index,
            "time": item.findtext("time") or "",
            "method": item.findtext("method") or "",
            "url": redact_text(url),
            "host": item.findtext("host") or "",
            "path": redact_text(item.findtext("path") or ""),
            "status": item.findtext("status") or "",
            "response_length": item.findtext("responselength") or "",
            "mime_type": item.findtext("mimetype") or "",
            "request_line": redact_text(request_line),
            "response_line": response_line,
            "query_params": query_params(url),
            "request_headers": request_headers,
            "response_headers": response_headers,
            "request_json": parse_json_body(request),
            "response_json": parse_json_body(response),
        })
    return summaries


def write_outputs(program: str, summaries: list[dict[str, object]]) -> None:
    out_dir = Path("programs") / program / "recon" / "burp-analysis"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "summary.json").write_text(json.dumps(summaries, indent=2, sort_keys=True) + "\n")
    with (out_dir / "summary.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["file", "index", "method", "host", "path", "status", "mime_type", "response_length"])
        writer.writeheader()
        for item in summaries:
            writer.writerow({name: item.get(name, "") for name in writer.fieldnames})


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze Burp XML exports with redaction.")
    parser.add_argument("program", help="Program folder name under programs/")
    parser.add_argument("files", nargs="+", help="Burp XML export files")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    summaries: list[dict[str, object]] = []
    for file_name in args.files:
        summaries.extend(analyze_file(Path(file_name)))
    write_outputs(args.program, summaries)
    print(f"Analyzed items: {len(summaries)}")
    print(f"Output: programs/{args.program}/recon/burp-analysis")
    for item in summaries:
        params = ", ".join(sorted((item.get("query_params") or {}).keys()))
        print(f"{item['method']} {item['host']}{item['path']} -> {item['status']} {item['mime_type']} params=[{params}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())