#!/usr/bin/env python3
"""Orchestrate the local bug bounty recon scripts for one program.

The default mode runs low-rate public recon and writes a redacted archive.
Active checks and Burp replay are opt-in because each program's rules differ.
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse


DEFAULT_RESEARCHER = "zx10r8443"
DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"


class HuntError(RuntimeError):
    pass


def initialize_program(program_dir: Path) -> None:
    program_dir.mkdir(parents=True, exist_ok=True)
    for child in ("recon", "evidence", "reports", "notes", "scripts/custom"):
        (program_dir / child).mkdir(parents=True, exist_ok=True)
    scope_template = Path("templates") / "scope.md"
    checklist_template = Path("templates") / "fast-hunt-checklist.md"
    scope_file = program_dir / "scope.md"
    checklist_file = program_dir / "notes" / "fast-hunt-checklist.md"
    targets_file = program_dir / "targets.txt"
    if scope_template.exists() and not scope_file.exists():
        scope_file.write_text(scope_template.read_text(encoding="utf-8"), encoding="utf-8")
    if checklist_template.exists() and not checklist_file.exists():
        checklist_file.write_text(checklist_template.read_text(encoding="utf-8"), encoding="utf-8")
    targets_file.touch(exist_ok=True)


def run_command(command: list[str], log_file: Path, dry_run: bool = False) -> int:
    printable = " ".join(command)
    print(f"[run] {printable}")
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(f"\n$ {printable}\n")
        if dry_run:
            handle.write("[dry-run] skipped\n")
            return 0
        process = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        handle.write(process.stdout)
        if process.returncode != 0:
            handle.write(f"[exit] {process.returncode}\n")
        return process.returncode


def load_targets(program_dir: Path) -> list[str]:
    targets_file = program_dir / "targets.txt"
    if not targets_file.exists():
        initialize_program(program_dir)
        raise HuntError(f"Initialized {program_dir}. Add in-scope assets to {targets_file}, then rerun.")
    targets = []
    for raw_line in targets_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line and not line.startswith("#"):
            targets.append(line)
    if not targets:
        raise HuntError(f"No targets in {targets_file}. Add in-scope assets, then rerun.")
    return targets


def normalize_seed(value: str) -> str:
    if value.startswith(("http://", "https://")):
        return value
    return f"https://{value.strip().lstrip('*.')}"


def discover_burp_files(program_dir: Path) -> list[Path]:
    burp_dir = program_dir / "evidence" / "burp"
    if not burp_dir.exists():
        return []
    return sorted(list(burp_dir.glob("*.req")) + list(burp_dir.glob("*.xml")))


def collect_query_urls(program_dir: Path) -> list[str]:
    urls: set[str] = set()
    query_csv = program_dir / "recon" / "param-crawler" / "query-params.csv"
    if query_csv.exists():
        with query_csv.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                url = (row.get("url") or "").strip()
                if urlparse(url).query:
                    urls.add(url)
    endpoints_csv = program_dir / "recon" / "js-endpoints" / "endpoints.csv"
    if endpoints_csv.exists():
        with endpoints_csv.open(newline="", encoding="utf-8") as handle:
            for row in csv.DictReader(handle):
                endpoint = (row.get("endpoint") or "").strip()
                if urlparse(endpoint).query:
                    urls.add(endpoint)
    return sorted(urls)


def write_safety_targets(program_dir: Path, max_targets: int) -> Path | None:
    urls = collect_query_urls(program_dir)[:max_targets]
    if not urls:
        return None
    out_dir = program_dir / "recon" / "fresh-candidates"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / "auto-targets.txt"
    out_file.write_text("\n".join(f"GET {url}" for url in urls) + "\n", encoding="utf-8")
    return out_file


def summarize_json_count(path: Path, key: str | None = None) -> int:
    if not path.exists():
        return 0
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return 0
    if key and isinstance(data, dict):
        value = data.get(key)
        return int(value) if isinstance(value, int) else 0
    if isinstance(data, list):
        return len(data)
    return 0


def write_hunt_summary(program: str, program_dir: Path, args: argparse.Namespace, archive_path: Path | None) -> Path:
    summary_path = program_dir / "notes" / "hunt-summary.md"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    crawler_meta = program_dir / "recon" / "param-crawler" / "metadata.json"
    js_meta = program_dir / "recon" / "js-endpoints" / "metadata.json"
    param_results = program_dir / "recon" / "basic-param-test" / "results.json"
    safety_results = program_dir / "recon" / "endpoint-safety-tests" / "results.json"
    burp_summary = program_dir / "recon" / "burp-analysis" / "summary.json"

    lines = [
        "# Hunt Summary",
        "",
        f"Program: {program}",
        f"Researcher: {args.researcher}",
        f"Generated: {datetime.now(timezone.utc).isoformat()}",
        "",
        "## Automation Run",
        "",
        f"- Passive recon: {'yes' if not args.skip_passive else 'skipped'}",
        f"- Crawler max pages: {args.max_pages}",
        f"- JavaScript extraction max scripts: {args.max_scripts}",
        f"- Active checks: {'yes' if args.active else 'no'}",
        f"- Burp processing: {'yes' if args.with_burp else 'no'}",
        "",
        "## Output Counts",
        "",
        f"- Crawled URLs: {summarize_json_count(crawler_meta, 'unique_urls')}",
        f"- Query parameters: {summarize_json_count(crawler_meta, 'query_parameters')}",
        f"- Form parameters: {summarize_json_count(crawler_meta, 'form_parameters')}",
        f"- JS endpoints: {summarize_json_count(js_meta, 'endpoints')}",
        f"- Basic parameter checks: {summarize_json_count(param_results)}",
        f"- Endpoint safety checks: {summarize_json_count(safety_results)}",
        f"- Burp analyzed items: {summarize_json_count(burp_summary)}",
        "",
        "## Review Next",
        "",
        "- `recon/js-endpoints/endpoints.csv` for hidden APIs.",
        "- `recon/endpoint-priorities/prioritized.csv` after Burp import.",
        "- `recon/auth-variant-tests/results.json` for missing-auth candidates.",
        "- `recon/endpoint-safety-tests/results.csv` for SQLi/command/traversal signals.",
        "- `evidence/` and `reports/` for confirmed findings only.",
    ]
    if archive_path:
        lines.extend(["", "## Archive", "", f"- {archive_path}"])
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return summary_path


def should_archive(path: Path, include_evidence: bool) -> bool:
    parts = set(path.parts)
    if "__pycache__" in parts:
        return False
    if "archives" in parts:
        return False
    if path.suffix in {".pyc", ".pyo"}:
        return False
    if not include_evidence and "evidence" in parts:
        return False
    if "private" in parts:
        return False
    return True


def create_archive(program: str, program_dir: Path, include_evidence: bool, replace_archive: bool) -> Path:
    archive_dir = Path("archives") / program
    archive_dir.mkdir(parents=True, exist_ok=True)
    if replace_archive:
        for old_archive in archive_dir.glob(f"{program}-hunt-*.tar.gz"):
            old_archive.unlink()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    archive_path = archive_dir / f"{program}-hunt-{stamp}.tar.gz"
    with tarfile.open(archive_path, "w:gz") as tar:
        for path in program_dir.rglob("*"):
            if path.is_file() and should_archive(path.relative_to(program_dir), include_evidence):
                tar.add(path, arcname=Path(program) / path.relative_to(program_dir))
    return archive_path


def latest_archive(program: str) -> Path | None:
    archive_dir = Path("archives") / program
    archives = sorted(archive_dir.glob(f"{program}-hunt-*.tar.gz"), key=lambda path: path.stat().st_mtime, reverse=True)
    return archives[0] if archives else None


def safe_tar_members(archive: tarfile.TarFile, program: str) -> list[tarfile.TarInfo]:
    members: list[tarfile.TarInfo] = []
    expected_prefix = f"{program}/"
    for member in archive.getmembers():
        member_path = Path(member.name)
        if member_path.is_absolute() or ".." in member_path.parts:
            raise HuntError(f"Unsafe archive member path: {member.name}")
        if member.name != program and not member.name.startswith(expected_prefix):
            raise HuntError(f"Archive does not look like a {program} archive: {member.name}")
        members.append(member)
    return members


def restore_archive(program: str, program_dir: Path, archive_path: Path | None, force: bool) -> Path:
    selected_archive = archive_path or latest_archive(program)
    if not selected_archive:
        raise HuntError(f"No archive found under archives/{program}/")
    if not selected_archive.exists():
        raise HuntError(f"Archive not found: {selected_archive}")
    if program_dir.exists() and any(program_dir.iterdir()) and not force:
        raise HuntError(f"{program_dir} already exists. Use --force-restore to replace it.")
    if program_dir.exists() and force:
        shutil.rmtree(program_dir)
    program_dir.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(selected_archive, "r:gz") as archive:
        members = safe_tar_members(archive, program)
        archive.extractall(program_dir.parent, members=members, filter="data")
    initialize_program(program_dir)
    return selected_archive


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the local bug bounty hunt workflow for one program.")
    parser.add_argument("program", help="Program folder name under programs/")
    parser.add_argument("--seed", action="append", help="Seed URL. Defaults to https:// for each target in targets.txt")
    parser.add_argument("--max-pages", type=int, default=30, help="Crawler page limit. Default: 30")
    parser.add_argument("--max-scripts", type=int, default=30, help="JS file inspection limit. Default: 30")
    parser.add_argument("--max-param-tests", type=int, default=20, help="Basic parameter test limit. Default: 20")
    parser.add_argument("--max-safety-targets", type=int, default=25, help="Endpoint safety target limit. Default: 25")
    parser.add_argument("--delay", type=float, default=2.0, help="Delay between active requests. Default: 2")
    parser.add_argument("--timeout", type=int, default=10, help="HTTP timeout seconds. Default: 10")
    parser.add_argument("--researcher", default=DEFAULT_RESEARCHER)
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT)
    parser.add_argument("--skip-passive", action="store_true", help="Skip passive DNS/header recon")
    parser.add_argument("--passive-plus", action="store_true", help="Run optional external recon tools when installed")
    parser.add_argument("--active", action="store_true", help="Run opt-in active parameter and endpoint safety checks")
    parser.add_argument("--with-burp", action="store_true", help="Analyze Burp exports and run auth variant checks when exports exist")
    parser.add_argument("--include-evidence", action="store_true", help="Include evidence files in archive. Private folders are still excluded.")
    parser.add_argument("--archive-only", action="store_true", help="Only write the hunt summary and archive; do not run recon or tests")
    parser.add_argument("--restore-archive", nargs="?", const="latest", help="Restore this program from an archive path, or latest when no path is provided")
    parser.add_argument("--force-restore", action="store_true", help="Replace an existing local program folder during --restore-archive")
    parser.add_argument("--replace-archive", action="store_true", help="Delete old archives for this program before writing the new archive")
    parser.add_argument("--purge-after-archive", action="store_true", help="Delete the local program folder after a successful archive is created")
    parser.add_argument("--no-archive", action="store_true", help="Do not create final tar.gz archive")
    parser.add_argument("--dry-run", action="store_true", help="Print commands without executing them")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path.cwd()
    program_dir = root / "programs" / args.program

    if args.restore_archive:
        archive_path = None if args.restore_archive == "latest" else Path(args.restore_archive)
        restored_from = restore_archive(args.program, program_dir, archive_path, args.force_restore)
        print(f"Restored {args.program} from {restored_from}")
        print(f"Program folder: {program_dir}")
        return 0

    if not program_dir.exists():
        initialize_program(program_dir)
        raise HuntError(f"Initialized {program_dir}. Add scope details and in-scope assets to targets.txt, then rerun.")

    targets = load_targets(program_dir)
    seeds = args.seed or [normalize_seed(target) for target in targets]
    run_dir = program_dir / "recon" / "hunt-automation"
    log_file = run_dir / "commands.log"
    run_dir.mkdir(parents=True, exist_ok=True)
    if log_file.exists():
        log_file.unlink()

    failures: list[str] = []

    if args.archive_only:
        print("[archive-only] skipping recon and tests")
    elif not args.skip_passive:
        code = run_command(["bash", "scripts/recon/passive-recon.sh", args.program], log_file, args.dry_run)
        if code:
            failures.append("passive-recon")

    if args.passive_plus and not args.archive_only:
        code = run_command(["bash", "scripts/recon/external-recon.sh", args.program], log_file, args.dry_run)
        if code:
            failures.append("external-recon")

    if not args.archive_only:
        crawler_cmd = [
            "python3", "scripts/recon/param-crawler.py", args.program,
            "--max-pages", str(args.max_pages),
            "--delay", str(args.delay),
            "--timeout", str(args.timeout),
            "--researcher", args.researcher,
            "--user-agent", args.user_agent,
        ]
        for seed in seeds:
            crawler_cmd.extend(["--seed", seed])
        code = run_command(crawler_cmd, log_file, args.dry_run)
        if code:
            failures.append("param-crawler")

        js_cmd = [
            "python3", "scripts/recon/js-endpoint-extractor.py", args.program,
            "--max-pages", str(args.max_pages),
            "--max-scripts", str(args.max_scripts),
            "--delay", str(args.delay),
            "--timeout", str(args.timeout),
            "--researcher", args.researcher,
            "--user-agent", args.user_agent,
        ]
        code = run_command(js_cmd, log_file, args.dry_run)
        if code:
            failures.append("js-endpoint-extractor")

    if args.active and not args.archive_only:
        basic_cmd = [
            "python3", "scripts/testing/basic-param-test.py", args.program,
            "--interesting-only",
            "--max-tests", str(args.max_param_tests),
            "--delay", str(args.delay),
            "--timeout", str(args.timeout),
            "--researcher", args.researcher,
            "--user-agent", args.user_agent,
        ]
        code = run_command(basic_cmd, log_file, args.dry_run)
        if code:
            failures.append("basic-param-test")

        safety_targets = None if args.dry_run else write_safety_targets(program_dir, args.max_safety_targets)
        if safety_targets:
            safety_cmd = [
                "python3", "scripts/testing/endpoint-safety-tester.py", args.program, str(safety_targets),
                "--delay", str(args.delay),
                "--timeout", str(args.timeout),
                "--researcher", args.researcher,
                "--user-agent", args.user_agent,
            ]
            code = run_command(safety_cmd, log_file, args.dry_run)
            if code:
                failures.append("endpoint-safety-tester")
        else:
            print("[skip] endpoint-safety-tester: no query-parameter targets found")

    if args.with_burp and not args.archive_only:
        burp_files = discover_burp_files(program_dir)
        if burp_files:
            burp_paths = [str(path) for path in burp_files]
            code = run_command(["python3", "scripts/burp/burp-analyze.py", args.program, *burp_paths], log_file, args.dry_run)
            if code:
                failures.append("burp-analyze")
            summary = program_dir / "recon" / "burp-analysis" / "summary.json"
            if summary.exists() or args.dry_run:
                code = run_command(["python3", "scripts/burp/endpoint-prioritizer.py", args.program, str(summary), "--researcher", args.researcher], log_file, args.dry_run)
                if code:
                    failures.append("endpoint-prioritizer")
            code = run_command(["python3", "scripts/burp/auth-variant-tester.py", args.program, *burp_paths, "--max-targets", "8", "--delay", str(args.delay)], log_file, args.dry_run)
            if code:
                failures.append("auth-variant-tester")
        else:
            print("[skip] Burp processing: no .req or .xml exports found")

    archive_path = None
    if not args.no_archive and not args.dry_run:
        archive_path = create_archive(args.program, program_dir, args.include_evidence, args.replace_archive)
    summary_path = None if args.dry_run else write_hunt_summary(args.program, program_dir, args, archive_path)

    purged_program = False
    if args.purge_after_archive:
        if args.no_archive or args.dry_run or not archive_path:
            print("[skip] purge-after-archive requires a completed archive")
        else:
            shutil.rmtree(program_dir)
            purged_program = True
            print(f"Purged local program folder: {program_dir}")

    if failures:
        print(f"Completed with failed steps: {', '.join(failures)}")
        print(f"Log: {log_file}")
        return 1
    print("Hunt automation complete")
    if summary_path and not purged_program:
        print(f"Summary: {summary_path}")
    if archive_path:
        print(f"Archive: {archive_path}")
    if not purged_program:
        print(f"Log: {log_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
