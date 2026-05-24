#!/usr/bin/env python3
"""Extract JavaScript files and likely endpoints from in-scope pages."""

from __future__ import annotations

import argparse
import csv
import html
import json
import re
import time
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen


DEFAULT_RESEARCHER = "zx10r8443"
DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
SCRIPT_TYPES = ("javascript", "ecmascript", "module", "")
ENDPOINT_RE = re.compile(r"(?P<quote>['\"])(?P<value>(?:https?://[^'\"\\\s]+|/[A-Za-z0-9_./?&=%:+,;@~-]{2,}|[A-Za-z0-9_.-]+/[A-Za-z0-9_./?&=%:+,;@~-]{2,}))(?P=quote)")
INTERESTING_RE = re.compile(r"api|auth|oauth|sso|login|logout|account|user|profile|token|session|course|cart|order|graphql|rest|v[0-9]/", re.I)


@dataclass(frozen=True)
class ScriptRef:
    page_url: str
    script_url: str


class ScriptParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.scripts: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "script":
            return
        attributes = {name.lower(): value or "" for name, value in attrs}
        script_type = attributes.get("type", "").lower()
        if not any(item in script_type for item in SCRIPT_TYPES):
            return
        src = attributes.get("src", "").strip()
        if src:
            self.scripts.add(urljoin(self.base_url, html.unescape(src)))


def load_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip().lower() for line in path.read_text().splitlines() if line.strip() and not line.startswith("#")]


def normalize_host(host: str) -> str:
    return host.lower().strip().lstrip("*.")


def clean_url(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return urlunparse(parsed._replace(fragment=""))


def is_allowed_host(host: str, allowed_roots: set[str], blocked_hosts: set[str]) -> bool:
    clean_host = host.lower().split(":", 1)[0]
    if clean_host in blocked_hosts:
        return False
    return any(clean_host == root or clean_host.endswith(f".{root}") for root in allowed_roots)


def fetch(url: str, timeout: int, user_agent: str, max_bytes: int) -> tuple[int, str, bytes]:
    request = Request(url, headers={"User-Agent": user_agent, "Accept": "text/html,application/javascript,text/javascript,*/*;q=0.1"})
    try:
        with urlopen(request, timeout=timeout) as response:
            content_type = response.headers.get("content-type", "").lower()
            return response.status, content_type, response.read(max_bytes)
    except HTTPError as error:
        content_type = error.headers.get("content-type", "").lower() if error.headers else ""
        return error.code, content_type, error.read(min(max_bytes, 200_000))


def load_seed_urls(args: argparse.Namespace, program_dir: Path) -> list[str]:
    seeds: list[str] = []
    if args.seed:
        seeds.extend(args.seed)
    if args.input_urls:
        seeds.extend(Path(args.input_urls).read_text().splitlines())
    default_urls = program_dir / "recon" / "param-crawler" / "urls.txt"
    if not seeds and default_urls.exists():
        seeds.extend(default_urls.read_text().splitlines())
    return [url for url in (clean_url(seed.strip()) for seed in seeds) if url]


def extract_scripts(page_url: str, body: bytes) -> set[str]:
    parser = ScriptParser(page_url)
    parser.feed(body.decode("utf-8", errors="replace"))
    return parser.scripts


def normalize_endpoint(raw_value: str, script_url: str) -> str | None:
    value = raw_value.strip()
    if value.startswith(("data:", "mailto:", "tel:", "javascript:")):
        return None
    if value.startswith("//"):
        value = f"https:{value}"
    if value.startswith("http://") or value.startswith("https://"):
        return clean_url(value)
    return clean_url(urljoin(script_url, value))


def extract_endpoints(script_url: str, body: bytes) -> set[str]:
    text = body.decode("utf-8", errors="replace")
    endpoints: set[str] = set()
    for match in ENDPOINT_RE.finditer(text):
        endpoint = normalize_endpoint(match.group("value"), script_url)
        if endpoint:
            endpoints.add(endpoint)
    return endpoints


def classify(endpoint: str) -> str:
    return "interesting" if INTERESTING_RE.search(endpoint) else "normal"


def run(args: argparse.Namespace) -> tuple[list[ScriptRef], list[dict[str, str]], list[dict[str, str]]]:
    program_dir = Path("programs") / args.program
    out_dir = program_dir / "recon" / "js-endpoints"
    out_dir.mkdir(parents=True, exist_ok=True)
    allowed_roots = {normalize_host(target) for target in load_lines(program_dir / "targets.txt")}
    blocked_hosts = set(load_lines(program_dir / "out-of-scope.txt"))
    seed_urls = load_seed_urls(args, program_dir)
    scripts: set[ScriptRef] = set()
    endpoints: list[dict[str, str]] = []
    errors: list[dict[str, str]] = []

    for page_url in seed_urls[: args.max_pages]:
        if not is_allowed_host(urlparse(page_url).netloc, allowed_roots, blocked_hosts):
            continue
        try:
            status, content_type, body = fetch(page_url, args.timeout, args.user_agent, 2_000_000)
        except (TimeoutError, URLError, OSError) as error:
            errors.append({"url": page_url, "error": str(error)})
            continue
        if status >= 500 or "html" not in content_type:
            time.sleep(args.delay)
            continue
        for script_url in extract_scripts(page_url, body):
            clean_script = clean_url(script_url)
            if clean_script and is_allowed_host(urlparse(clean_script).netloc, allowed_roots, blocked_hosts):
                scripts.add(ScriptRef(page_url, clean_script))
        time.sleep(args.delay)

    for script_ref in sorted(scripts, key=lambda item: item.script_url)[: args.max_scripts]:
        try:
            status, content_type, body = fetch(script_ref.script_url, args.timeout, args.user_agent, 5_000_000)
        except (TimeoutError, URLError, OSError) as error:
            errors.append({"url": script_ref.script_url, "error": str(error)})
            continue
        if status >= 500:
            time.sleep(args.delay)
            continue
        for endpoint in sorted(extract_endpoints(script_ref.script_url, body)):
            if is_allowed_host(urlparse(endpoint).netloc, allowed_roots, blocked_hosts):
                endpoints.append({
                    "researcher": args.researcher,
                    "source_script": script_ref.script_url,
                    "endpoint": endpoint,
                    "classification": classify(endpoint),
                })
        time.sleep(args.delay)

    metadata = {
        "researcher": args.researcher,
        "program": args.program,
        "seed_pages": len(seed_urls),
        "max_pages": args.max_pages,
        "max_scripts": args.max_scripts,
        "delay": args.delay,
        "timeout": args.timeout,
        "user_agent": args.user_agent,
        "scripts": len(scripts),
        "endpoints": len(endpoints),
        "interesting_endpoints": sum(1 for item in endpoints if item["classification"] == "interesting"),
        "errors": len(errors),
    }

    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    (out_dir / "errors.json").write_text(json.dumps(errors, indent=2, sort_keys=True) + "\n")
    with (out_dir / "scripts.csv").open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["page_url", "script_url"])
        for script in sorted(scripts, key=lambda item: (item.page_url, item.script_url)):
            writer.writerow([script.page_url, script.script_url])
    with (out_dir / "endpoints.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["researcher", "classification", "source_script", "endpoint"])
        writer.writeheader()
        writer.writerows(sorted(endpoints, key=lambda item: (item["classification"] != "interesting", item["endpoint"])))
    return sorted(scripts, key=lambda item: item.script_url), endpoints, errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract script URLs and likely endpoints from in-scope JavaScript files.")
    parser.add_argument("program", help="Program folder name under programs/")
    parser.add_argument("--seed", action="append", help="Seed page URL. May be used multiple times.")
    parser.add_argument("--input-urls", help="File containing page URLs. Defaults to param-crawler urls.txt when no seeds are supplied.")
    parser.add_argument("--max-pages", type=int, default=20, help="Maximum pages to inspect for scripts. Default: 20")
    parser.add_argument("--max-scripts", type=int, default=30, help="Maximum script files to inspect. Default: 30")
    parser.add_argument("--delay", type=float, default=1.5, help="Delay between requests in seconds. Default: 1.5")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds. Default: 10")
    parser.add_argument("--researcher", default=DEFAULT_RESEARCHER, help=f"Researcher username stamp. Default: {DEFAULT_RESEARCHER}")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="HTTP User-Agent header. Defaults to a Linux Chrome User-Agent string.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    scripts, endpoints, errors = run(args)
    print(f"Researcher: {args.researcher}")
    print(f"Scripts: {len(scripts)}")
    print(f"Endpoints: {len(endpoints)}")
    print(f"Interesting endpoints: {sum(1 for item in endpoints if item['classification'] == 'interesting')}")
    print(f"Errors: {len(errors)}")
    print(f"Output: programs/{args.program}/recon/js-endpoints")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())