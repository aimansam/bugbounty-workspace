#!/usr/bin/env python3
"""Summarize Burp XML exports with light redaction."""

from __future__ import annotations

import argparse
import base64
import csv
import json
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
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
    "api_key",
    "apikey",
    "batch_time",
    "captcha",
    "clienttime",
    "compiledversion",
    "contentencoding",
    "dd-api-key",
    "dd-request-id",
    "id_token",
    "ip",
    "ip_address",
    "ipaddress",
    "isnewsession",
    "lastactivity",
    "orgid",
    "pageid",
    "pagestart",
    "prevbundletime",
    "refresh_token",
    "password",
    "passwd",
    "phone",
    "phonecode",
    "seq",
    "secret",
    "sessionid",
    "email",
    "username",
    "user",
    "userid",
    "x-api-key",
    "x-forwarded-for",
}
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
PERSON_URN_RE = re.compile(r"urn:[^\s/?&\"']+")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
OPAQUE_VALUE_RE = re.compile(r"(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_=.~:/%+-]{48,}")
INLINE_OPAQUE_RE = re.compile(r"\b(?=[A-Za-z0-9_-]{32,}\b)(?=[A-Za-z0-9_-]*[A-Za-z])(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{32,}\b")
HEX32_RE = re.compile(r"\b[0-9a-f]{32}\b", re.IGNORECASE)
SENSITIVE_NORMALIZED_NAMES = {
    "accountid",
    "anonymousid",
    "bookingtoken",
    "code",
    "deeplinkuuid",
    "gaclientid",
    "gauid",
    "redirectid",
    "searchsessionid",
    "sessionid",
    "sid",
    "state",
    "uid",
    "userid",
}
INLINE_QUERY_NAMES = (
    "anonymousId",
    "booking_token",
    "code",
    "deeplink_uuid",
    "deeplinkUuid",
    "prebooking",
    "redirectId",
    "searchSessionId",
    "session_id",
    "sid",
    "state",
    "token",
    "uid",
    "userId",
)


def normalized_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]", "", name.lower())


def redact_embedded_query_values(value: str) -> str:
    for name in INLINE_QUERY_NAMES:
        value = re.sub(rf"([?&]{re.escape(name)}=)[^&\s\"']+", rf"\1[REDACTED]", value, flags=re.IGNORECASE)
        value = re.sub(rf"(%26{re.escape(name)}%3[Dd])(?:(?!%26)[^\s\"']+)", rf"\1[REDACTED]", value, flags=re.IGNORECASE)
    return value


def decode_element_text(element: ElementTree.Element | None) -> str:
    if element is None or element.text is None:
        return ""
    text = element.text
    if element.attrib.get("base64") == "true":
        return base64.b64decode(text).decode("utf-8", errors="replace")
    return text


def redact_name_value(name: str, value: str) -> str:
    name_lower = name.lower()
    normalized = normalized_name(name)
    if (
        name_lower in SENSITIVE_NAMES
        or normalized in SENSITIVE_NORMALIZED_NAMES
        or any(item in name_lower for item in ("token", "password", "secret", "session", "auth", "oauth", "api_key", "apikey"))
    ):
        return "[REDACTED]"
    if OPAQUE_VALUE_RE.fullmatch(value):
        return "[REDACTED_OPAQUE]"
    value = redact_text(value)
    if len(value) > 120:
        return f"{value[:80]}...[truncated:{len(value)}]"
    return value


def redact_text(value: str) -> str:
    value = redact_embedded_query_values(value)
    value = EMAIL_RE.sub("[REDACTED_EMAIL]", value)
    value = IPV4_RE.sub("[REDACTED_IP]", value)
    value = PERSON_URN_RE.sub("[REDACTED_PERSON_URN]", value)
    value = JWT_RE.sub("[REDACTED_JWT]", value)
    value = INLINE_OPAQUE_RE.sub("[REDACTED_OPAQUE]", value)
    value = HEX32_RE.sub("[REDACTED_HEX_ID]", value)
    return value


def redact_url(value: str) -> str:
    parsed = urlparse(value)
    if not parsed.query:
        return redact_text(value)
    redacted_pairs = []
    for name, child in parse_qsl(parsed.query, keep_blank_values=True):
        redacted_pairs.append((name, redact_name_value(name, child)))
    return redact_text(urlunparse(parsed._replace(query=urlencode(redacted_pairs, doseq=True))))


def redact_path_or_url(value: str) -> str:
    if not value:
        return value
    if "?" not in value:
        return redact_text(value)
    if value.startswith(("http://", "https://")):
        return redact_url(value)
    return redact_url(f"https://placeholder.local{value}").replace("https://placeholder.local", "", 1)


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


def redact_start_line(value: str) -> str:
    parts = value.split(" ")
    if len(parts) < 2:
        return redact_text(value)
    parts[1] = redact_path_or_url(parts[1])
    return redact_text(" ".join(parts))


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
            normalized = normalized_name(key)
            if (
                key_lower in SENSITIVE_NAMES
                or normalized in SENSITIVE_NORMALIZED_NAMES
                or any(item in key_lower for item in ("token", "password", "secret", "jwt", "captcha", "phone", "api_key", "apikey", "session"))
            ):
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
            "url": redact_url(url),
            "host": item.findtext("host") or "",
            "path": redact_path_or_url(item.findtext("path") or ""),
            "status": item.findtext("status") or "",
            "response_length": item.findtext("responselength") or "",
            "mime_type": item.findtext("mimetype") or "",
            "request_line": redact_start_line(request_line),
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