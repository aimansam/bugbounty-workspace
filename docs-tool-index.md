# Tool Index

All scripts are for authorized bug bounty programs only. Keep each run tied to the program scope and rules.

## Program Setup

- `scripts/core/new-program.sh` - creates `programs/<program>/` folders, scope file, target file, and a fast hunt checklist.
- `scripts/core/hunt-automate.py` - orchestrates passive recon, active discovery, optional parameter tests, optional Burp analysis, summary writing, and archiving.

## Script Placement

- Keep reusable, program-agnostic automation in the top-level `scripts/` categories.
- Put program-specific validators and one-off helpers in `programs/<program>/scripts/custom/`.
- Do not promote a custom script into top-level `scripts/` unless it can run safely across many programs.

## Recon

- `scripts/recon/passive-recon.sh` - DNS and HTTP header snapshot for targets in `targets.txt`.
- `scripts/recon/external-recon.sh` - optional broader passive recon using installed tools such as `subfinder`, `httpx`, `katana`, and `waybackurls`.
- `scripts/recon/param-crawler.py` - gentle in-scope crawler for URLs, query parameters, forms, and optional reflection checks.
- `scripts/recon/js-endpoint-extractor.py` - extracts JavaScript files and likely API endpoints from in-scope pages.

## Intel

- `scripts/intel/cve-watch.py` - maps local technology/version hints to conservative CVE candidates for manual validation.

## Parameter And Endpoint Checks

- `scripts/testing/basic-param-test.py` - low-rate marker reflection checks for interesting query parameters.
- `scripts/testing/endpoint-safety-tester.py` - conservative SQLi, command injection, and traversal signal checks for query-parameter endpoints.

## Burp-Based Analysis

- `scripts/burp/burp-analyze.py` - parses Burp XML exports and writes redacted summaries.
- `scripts/burp/endpoint-prioritizer.py` - scores redacted Burp summaries and creates a focused endpoint checklist.
- `scripts/burp/auth-variant-tester.py` - replays selected requests as no-auth and invalid-auth variants, saving metadata only.

## Common Runs

Recommended workflow order:

1. Passive recon: confirm scope and collect DNS/header/technology hints.
2. Active discovery: crawl gently and extract JavaScript endpoints.
3. Parameter testing: run focused reflection and endpoint safety checks only when allowed.
4. Burp analysis: import researcher-owned traffic, prioritize endpoints, and run metadata-only auth variants.

Create a program:

```bash
bash scripts/core/new-program.sh <program-name>
```

Default automation:

```bash
python3 scripts/core/hunt-automate.py <program-name>
```

Parameter tests when active testing is allowed:

```bash
python3 scripts/core/hunt-automate.py <program-name> --active --delay 2
```

Optional broader passive recon when allowed:

```bash
python3 scripts/core/hunt-automate.py <program-name> --passive-plus --delay 2
```

Passive CVE intelligence from local recon artifacts:

```bash
python3 scripts/intel/cve-watch.py <program-name>
```

Refresh public NVD cache when you want current CVE metadata:

```bash
python3 scripts/intel/cve-watch.py <program-name> --refresh-cve-cache
```

Burp processing after exporting traffic:

```bash
python3 scripts/core/hunt-automate.py <program-name> --with-burp
```

Archive without rerunning tests:

```bash
python3 scripts/core/hunt-automate.py <program-name> --archive-only
```

Delete old archives, write one fresh archive, and remove the local program folder after the archive is written:

```bash
python3 scripts/core/hunt-automate.py <program-name> --archive-only --replace-archive --purge-after-archive
```

Restore latest archive to continue a program:

```bash
python3 scripts/core/hunt-automate.py <program-name> --restore-archive
```
