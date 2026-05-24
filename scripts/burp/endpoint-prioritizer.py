#!/usr/bin/env python3
"""Prioritize endpoints from redacted Burp analysis summaries."""

from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlparse


DEFAULT_RESEARCHER = "zx10r8443"
NOISE_HOST_PARTS = (
    "google",
    "doubleclick",
    "recaptcha",
    "nr-data",
    "cookielaw",
    "facebook",
    "linkedin",
    "demdex",
    "adroll",
    "bing",
    "qualtrics",
    "mktoresp",
)
STATIC_EXTENSIONS = (".js", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".otf", ".eot", ".ico")
HIGH_VALUE_PATH_TERMS = ("/api/", "/users/", "/user/", "/account", "login", "logout", "access", "status", "pendo", "profile", "cart", "checkout", "order")
SENSITIVE_KEYS = {
    "access_token",
    "affiliations",
    "apiKey",
    "client_id",
    "customJwt",
    "email",
    "familyName",
    "givenName",
    "person_xid",
    "personXid",
    "professionalAdditionalInfo",
    "rmsSessionId",
    "session_id",
    "session_xid",
    "userType",
    "visitor",
    "xid",
}


def load_items(paths: list[Path]) -> list[dict[str, object]]:
    items: list[dict[str, object]] = []
    for path in paths:
        for item in json.loads(path.read_text()):
            item["summary_file"] = str(path)
            items.append(item)
    return items


def is_noise(item: dict[str, object]) -> bool:
    host = str(item.get("host", "")).lower()
    path = str(item.get("path", "")).lower().split("?", 1)[0]
    if any(part in host for part in NOISE_HOST_PARTS):
        return True
    return path.endswith(STATIC_EXTENSIONS)


def response_keys(item: dict[str, object]) -> list[str]:
    response_json = item.get("response_json")
    if isinstance(response_json, dict):
        return sorted(response_json.keys())
    return []


def request_keys(item: dict[str, object]) -> list[str]:
    request_json = item.get("request_json")
    if isinstance(request_json, dict):
        return sorted(request_json.keys())
    return []


def score_item(item: dict[str, object]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    method = str(item.get("method", ""))
    host = str(item.get("host", ""))
    path = str(item.get("path", ""))
    status = str(item.get("status", ""))
    keys = response_keys(item)
    lower_path = path.lower()

    if host:
        score += 10
        reasons.append("captured host")
    if any(term in lower_path for term in HIGH_VALUE_PATH_TERMS):
        score += 20
        reasons.append("high-value path")
    if status == "200":
        score += 10
        reasons.append("successful response")
    if method not in {"OPTIONS", "GET"}:
        score += 5
        reasons.append("state-changing or login method")
    if keys:
        score += 10
        reasons.append("structured JSON")
    sensitive_overlap = sorted(set(keys) & SENSITIVE_KEYS)
    if sensitive_overlap:
        score += 30
        reasons.append(f"sensitive-shaped keys: {'|'.join(sensitive_overlap)}")
    if is_noise(item):
        score -= 100
        reasons.append("noise/static/third-party")
    return score, reasons


def endpoint_key(item: dict[str, object]) -> tuple[str, str, str]:
    path = str(item.get("path", "")).split("?", 1)[0]
    return str(item.get("method", "")), str(item.get("host", "")), path


def prioritize(items: list[dict[str, object]]) -> list[dict[str, object]]:
    best: dict[tuple[str, str, str], dict[str, object]] = {}
    for item in items:
        score, reasons = score_item(item)
        key = endpoint_key(item)
        candidate = {
            "score": score,
            "reasons": reasons,
            "method": item.get("method", ""),
            "host": item.get("host", ""),
            "path": key[2],
            "status": item.get("status", ""),
            "mime_type": item.get("mime_type", ""),
            "request_keys": request_keys(item),
            "response_keys": response_keys(item),
            "summary_file": item.get("summary_file", ""),
        }
        if key not in best or score > int(best[key]["score"]):
            best[key] = candidate
    return sorted(best.values(), key=lambda entry: (-int(entry["score"]), str(entry["host"]), str(entry["path"])))


def cluster_shapes(items: list[dict[str, object]]) -> list[dict[str, object]]:
    clusters: dict[tuple[str, ...], dict[str, object]] = {}
    counts: Counter[tuple[str, ...]] = Counter()
    examples: defaultdict[tuple[str, ...], list[str]] = defaultdict(list)
    for item in items:
        keys = tuple(response_keys(item))
        if not keys:
            continue
        counts[keys] += 1
        example = f"{item.get('method')} {item.get('host')}{str(item.get('path', '')).split('?', 1)[0]}"
        if len(examples[keys]) < 5:
            examples[keys].append(example)
    for keys, count in counts.items():
        clusters[keys] = {"count": count, "response_keys": list(keys), "examples": examples[keys]}
    return sorted(clusters.values(), key=lambda entry: (-int(entry["count"]), entry["response_keys"]))


def write_outputs(program: str, prioritized: list[dict[str, object]], clusters: list[dict[str, object]], args: argparse.Namespace) -> None:
    out_dir = Path("programs") / program / "recon" / "endpoint-priorities"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "prioritized.json").write_text(json.dumps(prioritized, indent=2, sort_keys=True) + "\n")
    (out_dir / "clusters.json").write_text(json.dumps(clusters, indent=2, sort_keys=True) + "\n")

    with (out_dir / "prioritized.csv").open("w", newline="") as handle:
        fieldnames = ["score", "method", "host", "path", "status", "mime_type", "reasons", "request_keys", "response_keys"]
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for item in prioritized:
            writer.writerow({
                "score": item["score"],
                "method": item["method"],
                "host": item["host"],
                "path": item["path"],
                "status": item["status"],
                "mime_type": item["mime_type"],
                "reasons": " | ".join(item["reasons"]),
                "request_keys": "|".join(item["request_keys"]),
                "response_keys": "|".join(item["response_keys"]),
            })

    top = [item for item in prioritized if int(item["score"]) > 0][:15]
    checklist = ["# Endpoint Testing Checklist", "", f"Researcher: {args.researcher}", "", "## Top Priorities", ""]
    for index, item in enumerate(top, start=1):
        checklist.extend([
            f"### {index}. {item['method']} {item['host']}{item['path']}",
            "",
            f"- Score: {item['score']}",
            f"- Status seen: {item['status']}",
            f"- Reasons: {', '.join(item['reasons'])}",
            f"- Response keys: {', '.join(item['response_keys']) or 'none'}",
            "- Safe checks:",
            "  - Confirm expected auth requirement.",
            "  - Confirm no user-specific data with missing/invalid auth.",
            "  - Compare only researcher-owned account data.",
            "  - Do not brute force, fuzz, or test third-party users.",
            "",
        ])
    (out_dir / "checklist.md").write_text("\n".join(checklist))


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Prioritize endpoints from redacted Burp summaries.")
    parser.add_argument("program", help="Program folder name under programs/")
    parser.add_argument("summaries", nargs="+", help="Redacted burp-analyze summary JSON files")
    parser.add_argument("--researcher", default=DEFAULT_RESEARCHER, help=f"Researcher username stamp. Default: {DEFAULT_RESEARCHER}")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    items = load_items([Path(summary) for summary in args.summaries])
    prioritized = prioritize(items)
    clusters = cluster_shapes(items)
    write_outputs(args.program, prioritized, clusters, args)
    print(f"Loaded items: {len(items)}")
    print(f"Unique endpoints: {len(prioritized)}")
    print(f"Response clusters: {len(clusters)}")
    print(f"Output: programs/{args.program}/recon/endpoint-priorities")
    for item in prioritized[:10]:
        print(f"{item['score']:>3} {item['method']} {item['host']}{item['path']} -> {item['status']} [{', '.join(item['reasons'])}]")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())