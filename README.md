# Bug Bounty Workspace

This workspace is for authorized bug bounty work only. Keep every test tied to a program scope, rules of engagement, and written permission.

## Workflow

1. Pick a program and save its rules in `programs/<program-name>/scope.md`.
2. Add in-scope assets to `programs/<program-name>/targets.txt`.
3. Run passive recon first and save outputs under `programs/<program-name>/recon/`.
4. Move to active testing only when the program allows it.
5. Save screenshots, requests, responses, and reproduction notes under `programs/<program-name>/evidence/`.
6. Draft reports in `programs/<program-name>/reports/`.

For a repeatable new-scope routine, start with [templates/fast-hunt-checklist.md](templates/fast-hunt-checklist.md).

## Automated Hunt Run

Use `scripts/core/hunt-automate.py` to run the local workflow for a program and create a final archive.

Public/passive default run:

```bash
python3 scripts/core/hunt-automate.py <program-name>
```

This runs passive recon, the parameter crawler, JavaScript endpoint extraction, writes `programs/<program-name>/notes/hunt-summary.md`, and creates a `.tar.gz` archive under `archives/<program-name>/`.

When active testing is allowed by the program rules, add `--active`:

```bash
python3 scripts/core/hunt-automate.py <program-name> --active --delay 2
```

This adds basic parameter checks and conservative endpoint safety tests for query-parameter URLs discovered during crawling and JavaScript extraction.

When broader passive recon is allowed and optional tools are installed, add `--passive-plus`:

```bash
python3 scripts/core/hunt-automate.py <program-name> --passive-plus --delay 2
```

This runs `scripts/recon/external-recon.sh`, which uses available tools such as `subfinder`, `httpx`, `katana`, and `waybackurls`. Missing tools are recorded instead of failing the run.

After exporting Burp XML traffic to `programs/<program-name>/evidence/burp/`, add `--with-burp`:

```bash
python3 scripts/core/hunt-automate.py <program-name> --with-burp
```

This runs redacted Burp analysis, endpoint prioritization, and auth variant checks.

Useful combined run after you have confirmed active testing is allowed and captured researcher-owned account flows:

```bash
python3 scripts/core/hunt-automate.py <program-name> --active --with-burp --delay 2
```

Archives exclude `evidence/` by default to reduce the chance of bundling raw requests, cookies, or tokens. Use `--include-evidence` only when you intentionally want evidence files included; `private/` folders are still excluded.

To archive a program without rerunning recon or tests:

```bash
python3 scripts/core/hunt-automate.py <program-name> --archive-only
```

To delete old archives, write one fresh archive, and then delete the local program folder after the archive is created:

```bash
python3 scripts/core/hunt-automate.py <program-name> --archive-only --replace-archive --purge-after-archive
```

To continue a program later from the latest saved archive:

```bash
python3 scripts/core/hunt-automate.py <program-name> --restore-archive
```

To restore from a specific archive file:

```bash
python3 scripts/core/hunt-automate.py <program-name> --restore-archive archives/<program-name>/<archive>.tar.gz
```

If the local program folder already exists and you intentionally want to replace it, add `--force-restore`.

## Directory Layout

- `programs/` - one folder per bug bounty program
- `scripts/` - local helper scripts we build
- `wordlists/` - custom wordlists and payload notes
- `templates/` - reusable report and scope templates
- `notes/` - methodology notes and checklists

See [docs-tool-index.md](docs-tool-index.md) for a quick map of every script and when to use it.

The entire `programs/` folder and top-level `archives/` folder are ignored by Git. Public repositories should contain only the generic toolkit; create local program folders after cloning with `scripts/core/new-program.sh` or `scripts/core/hunt-automate.py`.

Keep reusable scripts in the top-level `scripts/` folder. Put target-specific validators, one-off PoCs, or program-only helpers under `programs/<program-name>/scripts/custom/` so they stay local with that program's notes and evidence.

This workspace also includes Copilot context files:

- [.github/copilot-instructions.md](.github/copilot-instructions.md) - always-on workspace guidance for future sessions.
- [.github/prompts/new-scope-hunt.prompt.md](.github/prompts/new-scope-hunt.prompt.md) - reusable prompt for starting a new authorized scope.

## Safety Rules

- Test only assets explicitly listed as in-scope.
- Respect rate limits and forbidden techniques.
- Do not access, modify, delete, or exfiltrate other users' data.
- Stop immediately if testing causes instability.
- Keep clean evidence and minimal proof-of-concept steps.

## Parameter Crawling

Use `scripts/recon/param-crawler.py` for gentle in-scope crawling, URL/query parameter inventory, form parameter inventory, and basic GET parameter reflection checks. It uses a Linux Chrome User-Agent string by default.

Example:

```bash
python3 scripts/recon/param-crawler.py example-program \
	--seed https://app.example.com/ \
	--max-pages 20 \
	--delay 2
```

Enable basic parameter reflection checks only after confirming the target is in scope and active testing is allowed:

```bash
python3 scripts/recon/param-crawler.py example-program \
	--seed https://app.example.com/ \
	--max-pages 20 \
	--delay 2 \
	--test-params \
	--max-tests 10
```

Outputs are saved under `programs/<program-name>/recon/param-crawler/`.

Run focused parameter checks from crawler output with:

```bash
python3 scripts/testing/basic-param-test.py example-program \
	--interesting-only \
	--max-tests 10 \
	--delay 2
```

Outputs are saved under `programs/<program-name>/recon/basic-param-test/`.

The crawler stamps metadata and basic findings with researcher username `zx10r8443` by default. Override it when needed:

```bash
python3 scripts/recon/param-crawler.py example-program \
	--seed https://app.example.com/ \
	--researcher zx10r8443
```

## JavaScript Endpoint Extraction

Use `scripts/recon/js-endpoint-extractor.py` to inspect in-scope pages for script files, then extract likely API/auth/account endpoints from those JavaScript files.

```bash
python3 scripts/recon/js-endpoint-extractor.py example-program \
	--max-pages 10 \
	--max-scripts 15 \
	--delay 2
```

Outputs are saved under `programs/<program-name>/recon/js-endpoints/`.

## External Recon

Use `scripts/recon/external-recon.sh` for optional broader passive discovery when the program allows it.

```bash
bash scripts/recon/external-recon.sh example-program
```

Outputs are saved under `programs/<program-name>/recon/external-recon/`.

## Auth Variant Testing

Use `scripts/burp/auth-variant-tester.py` to replay safe no-auth and invalid-auth variants from Burp XML exports. The script avoids printing cookies, tokens, passwords, or response bodies.

```bash
python3 scripts/burp/auth-variant-tester.py example-program \
	programs/example-program/evidence/burp/account-a.req \
	programs/example-program/evidence/burp/account-b.req \
	--max-targets 6 \
	--delay 2
```

Outputs are saved under `programs/<program-name>/recon/auth-variant-tests/`.

## Endpoint Prioritization

Use `scripts/burp/endpoint-prioritizer.py` to score redacted Burp summaries, cluster response shapes, and generate a focused checklist.

```bash
python3 scripts/burp/endpoint-prioritizer.py example-program \
	programs/example-program/recon/burp-analysis/account-a-summary.json \
	programs/example-program/recon/burp-analysis/account-b-summary.json
```

Outputs are saved under `programs/<program-name>/recon/endpoint-priorities/`.
