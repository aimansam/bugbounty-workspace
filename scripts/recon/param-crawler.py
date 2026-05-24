#!/usr/bin/env python3
"""Gentle in-scope crawler and basic parameter tester for bug bounty recon."""

from __future__ import annotations

import argparse
import csv
import html
import json
import time
from collections import deque
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen


DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
DEFAULT_RESEARCHER = "zx10r8443"
MARKER = "bbparamtest12345"
TEXT_TYPES = ("text/html", "application/xhtml+xml")


@dataclass(frozen=True)
class FormParam:
    page_url: str
    action: str
    method: str
    name: str
    input_type: str


@dataclass
class CrawlState:
    visited: set[str] = field(default_factory=set)
    queued: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)
    query_params: set[tuple[str, str]] = field(default_factory=set)
    forms: set[FormParam] = field(default_factory=set)
    findings: list[dict[str, str | int]] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)


class LinkAndFormParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__()
        self.base_url = base_url
        self.links: set[str] = set()
        self.forms: list[dict[str, str]] = []
        self._current_form: dict[str, str] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): value or "" for name, value in attrs}
        if tag.lower() in {"a", "area"} and attributes.get("href"):
            self.links.add(urljoin(self.base_url, html.unescape(attributes["href"])))
        elif tag.lower() == "form":
            action = attributes.get("action") or self.base_url
            method = attributes.get("method", "get").lower()
            self._current_form = {
                "action": urljoin(self.base_url, html.unescape(action)),
                "method": method,
            }
        elif tag.lower() in {"input", "textarea", "select", "button"} and self._current_form:
            name = attributes.get("name", "").strip()
            if name:
                input_type = attributes.get("type", tag.lower()).lower()
                self.forms.append({**self._current_form, "name": name, "input_type": input_type})

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self._current_form = None


def load_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line.strip().lower() for line in path.read_text().splitlines() if line.strip() and not line.startswith("#")]


def normalize_host(host: str) -> str:
    return host.lower().strip().lstrip("*.")


def normalize_url(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    clean = parsed._replace(fragment="")
    path = clean.path or "/"
    clean = clean._replace(path=path)
    return urlunparse(clean)


def strip_query(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(query="", fragment=""))


def is_allowed_host(host: str, allowed_roots: Iterable[str], blocked_hosts: Iterable[str]) -> bool:
    clean_host = host.lower().split(":", 1)[0]
    if clean_host in blocked_hosts:
        return False
    return any(clean_host == root or clean_host.endswith(f".{root}") for root in allowed_roots)


def fetch(url: str, timeout: int, user_agent: str) -> tuple[int, str, bytes]:
    request = Request(url, headers={"User-Agent": user_agent, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1"})
    try:
        with urlopen(request, timeout=timeout) as response:
            content_type = response.headers.get("content-type", "").lower()
            return response.status, content_type, response.read(2_000_000)
    except HTTPError as error:
        content_type = error.headers.get("content-type", "").lower() if error.headers else ""
        return error.code, content_type, error.read(200_000)


def extract_query_params(url: str) -> set[tuple[str, str]]:
    parsed = urlparse(url)
    return {(strip_query(url), name) for name, _ in parse_qsl(parsed.query, keep_blank_values=True)}


def test_query_reflection(url: str, param: str, timeout: int, researcher: str, user_agent: str) -> dict[str, str | int] | None:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    updated = [(name, MARKER if name == param else value) for name, value in pairs]
    if not any(name == param for name, _ in updated):
        updated.append((param, MARKER))
    test_url = urlunparse(parsed._replace(query=urlencode(updated, doseq=True)))
    status, content_type, body = fetch(test_url, timeout, user_agent)
    if MARKER.encode() in body:
        return {
            "researcher": researcher,
            "type": "reflected-query-param",
            "url": test_url,
            "param": param,
            "status": status,
            "content_type": content_type,
        }
    return None


def write_outputs(program_dir: Path, state: CrawlState, args: argparse.Namespace) -> None:
    out_dir = program_dir / "recon" / "param-crawler"
    out_dir.mkdir(parents=True, exist_ok=True)

    metadata = {
        "researcher": args.researcher,
        "program": args.program,
        "seeds": args.seed,
        "max_pages": args.max_pages,
        "delay": args.delay,
        "timeout": args.timeout,
        "same_path_prefix": args.same_path_prefix,
        "test_params": args.test_params,
        "max_tests": args.max_tests,
        "user_agent": args.user_agent,
        "visited_pages": len(state.visited),
        "unique_urls": len(state.urls),
        "query_parameters": len(state.query_params),
        "form_parameters": len(state.forms),
        "basic_findings": len(state.findings),
        "errors": len(state.errors),
    }

    (out_dir / "urls.txt").write_text("\n".join(sorted(state.urls)) + "\n")
    (out_dir / "metadata.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    (out_dir / "findings.json").write_text(json.dumps(state.findings, indent=2, sort_keys=True) + "\n")
    (out_dir / "errors.json").write_text(json.dumps(state.errors, indent=2, sort_keys=True) + "\n")

    with (out_dir / "query-params.csv").open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["url", "parameter"])
        writer.writerows(sorted(state.query_params))

    with (out_dir / "forms.csv").open("w", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["page_url", "action", "method", "name", "input_type"])
        for form in sorted(state.forms, key=lambda item: (item.page_url, item.action, item.name)):
            writer.writerow([form.page_url, form.action, form.method, form.name, form.input_type])


def crawl(args: argparse.Namespace) -> CrawlState:
    program_dir = Path("programs") / args.program
    allowed_roots = {normalize_host(target) for target in load_lines(program_dir / "targets.txt")}
    blocked_hosts = set(load_lines(program_dir / "out-of-scope.txt"))
    seeds = [normalize_url(seed) for seed in args.seed]
    queue = deque(seed for seed in seeds if seed)
    state = CrawlState(queued=set(queue))

    while queue and len(state.visited) < args.max_pages:
        url = queue.popleft()
        state.queued.discard(url)
        if url in state.visited:
            continue
        parsed = urlparse(url)
        if not is_allowed_host(parsed.netloc, allowed_roots, blocked_hosts):
            continue

        state.visited.add(url)
        state.urls.add(url)
        state.query_params.update(extract_query_params(url))
        try:
            status, content_type, body = fetch(url, args.timeout, args.user_agent)
        except (TimeoutError, URLError, OSError) as error:
            state.errors.append({"url": url, "error": str(error)})
            continue

        if status >= 500:
            time.sleep(args.delay)
            continue
        if not any(content_type.startswith(text_type) for text_type in TEXT_TYPES):
            time.sleep(args.delay)
            continue

        text = body.decode("utf-8", errors="replace")
        parser = LinkAndFormParser(url)
        parser.feed(text)
        for form in parser.forms:
            action_host = urlparse(form["action"]).netloc
            if is_allowed_host(action_host, allowed_roots, blocked_hosts):
                state.forms.add(FormParam(url, form["action"], form["method"], form["name"], form["input_type"]))

        for link in parser.links:
            normalized = normalize_url(link)
            if not normalized:
                continue
            link_host = urlparse(normalized).netloc
            if not is_allowed_host(link_host, allowed_roots, blocked_hosts):
                continue
            if args.same_path_prefix and not urlparse(normalized).path.startswith(args.same_path_prefix):
                continue
            state.query_params.update(extract_query_params(normalized))
            if normalized not in state.visited and normalized not in state.queued:
                queue.append(normalized)
                state.queued.add(normalized)

        time.sleep(args.delay)

    if args.test_params:
        tested = 0
        for base_url, param in sorted(state.query_params):
            if tested >= args.max_tests:
                break
            parsed = urlparse(base_url)
            if not is_allowed_host(parsed.netloc, allowed_roots, blocked_hosts):
                continue
            try:
                finding = test_query_reflection(base_url, param, args.timeout, args.researcher, args.user_agent)
            except (TimeoutError, URLError, OSError) as error:
                state.errors.append({"url": base_url, "error": str(error)})
                continue
            if finding:
                state.findings.append(finding)
            tested += 1
            time.sleep(args.delay)

    write_outputs(program_dir, state, args)
    return state


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="In-scope crawler, parameter inventory, and basic reflection tester.")
    parser.add_argument("program", help="Program folder name under programs/")
    parser.add_argument("--seed", action="append", required=True, help="Seed URL. May be used multiple times.")
    parser.add_argument("--max-pages", type=int, default=50, help="Maximum pages to fetch. Default: 50")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests in seconds. Default: 1.0")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout in seconds. Default: 10")
    parser.add_argument("--same-path-prefix", default="", help="Optional path prefix constraint, such as /highered")
    parser.add_argument("--test-params", action="store_true", help="Perform basic GET parameter reflection checks")
    parser.add_argument("--max-tests", type=int, default=25, help="Maximum parameter tests when --test-params is enabled. Default: 25")
    parser.add_argument("--researcher", default=DEFAULT_RESEARCHER, help=f"Researcher username stamp. Default: {DEFAULT_RESEARCHER}")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="HTTP User-Agent header. Defaults to a Linux Chrome User-Agent string.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    state = crawl(args)
    print(f"Researcher: {args.researcher}")
    print(f"User-Agent: {args.user_agent}")
    print(f"Visited pages: {len(state.visited)}")
    print(f"Unique URLs: {len(state.urls)}")
    print(f"Query parameters: {len(state.query_params)}")
    print(f"Form parameters: {len(state.forms)}")
    print(f"Basic findings: {len(state.findings)}")
    print(f"Errors: {len(state.errors)}")
    print(f"Output: programs/{args.program}/recon/param-crawler")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())