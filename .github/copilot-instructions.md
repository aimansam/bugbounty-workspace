# Bug Bounty Workspace Instructions

This workspace is an authorized bug bounty automation toolkit. Treat all testing as scope-bound, low-noise, and evidence-driven.

## Safety Defaults

- Work only from written program scope and rules in `programs/<program>/scope.md` and `targets.txt`.
- Do not run destructive tests, brute force, DoS, phishing, social engineering, spam, or third-party/vendor testing.
- Use researcher-owned accounts only.
- Do not access, modify, delete, or exfiltrate other users' data.
- Keep raw Burp exports, cookies, tokens, passwords, emails, and private evidence local and out of GitHub.
- Prefer metadata-only outputs and redaction over saving full response bodies.

## Repository Model

- Public GitHub should contain generic tooling only: `scripts/`, `templates/`, `notes/`, docs, and `.gitignore`.
- The entire `programs/` folder is local-only and ignored by Git.
- Reusable scripts go in top-level `scripts/`; program-specific validators or one-off helpers go in `programs/<program>/scripts/custom/`.
- If `programs/` or a program folder is missing, create it from templates before running automation.

## Standard Workflow

1. Create a program with `bash scripts/core/new-program.sh <program>` or let `scripts/core/hunt-automate.py <program>` initialize it.
2. Save scope/rules in `programs/<program>/scope.md` and in-scope targets in `programs/<program>/targets.txt`.
3. Start with passive/default automation:
   `python3 scripts/core/hunt-automate.py <program>`
4. Treat the workflow order as passive recon, active discovery, parameter testing, then Burp analysis.
5. Use `--passive-plus` only when broader passive discovery is allowed and useful.
6. Use `--active` only after confirming parameter testing is allowed.
7. Use `--with-burp` after the user exports researcher-owned Burp traffic to `programs/<program>/evidence/burp/`.
8. Use `--archive-only` to close a program without rerunning tests.

## Tool Priority

- `scripts/core/hunt-automate.py`: orchestrates passive recon, active discovery, parameter tests, Burp analysis, writes summaries, creates archives.
- `scripts/recon/passive-recon.sh`: DNS/header snapshot.
- `scripts/recon/external-recon.sh`: optional broader passive recon with available external tools.
- `scripts/recon/param-crawler.py`: gentle URL/query/form inventory.
- `scripts/recon/js-endpoint-extractor.py`: JavaScript endpoint discovery.
- `scripts/intel/cve-watch.py`: passive technology/version extraction and conservative CVE candidate mapping.
- `scripts/testing/basic-param-test.py`: low-rate reflection checks.
- `scripts/testing/endpoint-safety-tester.py`: conservative SQLi/command/traversal signals.
- `scripts/burp/burp-analyze.py`: redacted Burp XML summaries.
- `scripts/burp/endpoint-prioritizer.py`: endpoint scoring from redacted summaries.
- `scripts/burp/auth-variant-tester.py`: no-auth and invalid-auth metadata checks.

## Hunting Focus

Prioritize fast, reportable leads:

- Missing auth on sensitive API responses.
- Read-only authorization bugs when allowed.
- Token or secret exposure in JavaScript/config/API responses.
- CORS with credentials and attacker-controlled origin.
- Traversal on download/export/file endpoints.
- Clear backend error disclosure from search/filter parameters.
- Password reset, invite, email change, or recovery logic flaws.

Treat CVE matches as leads only. A version/CVE match is not reportable until reachable in-scope impact is manually confirmed.

Usually avoid low-value leads unless there is strong impact:

- Generic 500s.
- Missing headers.
- Clickjacking alone.
- Open redirect alone.
- Public config alone.
- Self-XSS or purely cosmetic issues.

## Reporting Style

- Confirm positive and negative controls before drafting.
- Use concise reproduction steps and redacted evidence.
- State impact conservatively and tie it to account security or business data.
- Do not include secrets, raw cookies, bearer tokens, raw emails, or customer data.
