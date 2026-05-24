# Fast Hunt Checklist

Use this when starting a new authorized program. Keep testing inside written scope and avoid noisy/destructive checks.

## 0. Scope Gate

- Save rules in `programs/<program>/scope.md`.
- Save in-scope roots in `programs/<program>/targets.txt`.
- Mark forbidden testing, rate limits, third-party exclusions, and auth/account rules.
- Pick one target app first; do not spread across the whole scope on day one.

## 1. Quick Recon

```bash
bash scripts/recon/passive-recon.sh <program>
python3 scripts/recon/param-crawler.py <program> --seed https://target.example/ --max-pages 30 --delay 2
python3 scripts/recon/js-endpoint-extractor.py <program> --max-pages 15 --max-scripts 30 --delay 2
python3 scripts/testing/basic-param-test.py <program> --interesting-only --max-tests 20 --delay 2
```

Optional broader passive recon when allowed:

```bash
bash scripts/recon/external-recon.sh <program>
```

Look for:

- Account, profile, billing, entitlement, invite, admin, export, file, download, and search endpoints.
- Parameters like `id`, `userId`, `accountId`, `orgId`, `email`, `role`, `redirect`, `next`, `url`, `file`, `path`, `format`, `query`, `q`.
- JavaScript routes or API hosts that are not visible in normal navigation.

## 2. Capture Real App Flows

Use Burp with two researcher-owned accounts when allowed.

High-value flows to capture:

- Login, logout, password reset, email change.
- Profile, account settings, saved addresses, billing, receipts.
- Organization/team/course/workspace membership.
- Content viewer, file download, PDF/export, media access.
- Search, filters, autocomplete, upload/import.
- Invitations, roles, sharing, subscriptions, entitlements.

Export Burp XML to `programs/<program>/evidence/burp/`.

## 3. Mine The Capture

```bash
python3 scripts/burp/burp-analyze.py <program> programs/<program>/evidence/burp/*.req
python3 scripts/burp/endpoint-prioritizer.py <program> programs/<program>/recon/burp-analysis/summary.json
```

Prioritize endpoints with:

- Authenticated `200` responses containing account or business objects.
- IDs in path, query, or JSON body.
- State-dependent data: entitlement, role, subscription, order, license, tenant, course, workspace.
- Different responses between account A and account B.

## 4. Fast Read-Only Bug Checks

```bash
python3 scripts/burp/auth-variant-tester.py <program> programs/<program>/evidence/burp/*.req --max-targets 8 --delay 2
python3 scripts/testing/endpoint-safety-tester.py <program> programs/<program>/recon/fresh-candidates/targets.txt --delay 2 --timeout 10
```

Good early bug classes:

- Missing auth on user/account/business data endpoints.
- Broken object-level authorization with read-only proof, only if allowed.
- Token or secret exposure in JavaScript/config/API responses.
- CORS with credentials and attacker-controlled origin.
- File/path traversal on download/export endpoints.
- Search/filter SQL or backend error disclosure with clear error signatures.
- Password reset or invite flow logic flaws.

Usually low-value by itself:

- Missing security headers.
- Clickjacking without sensitive action impact.
- Open redirect without token theft or trusted-domain impact.
- Generic public config.
- Generic `500` without useful error details.
- Reflected self-XSS or purely cosmetic issues.

## 5. Report Decision

Before writing a report, confirm:

- Clean positive and negative control.
- Repro works in a fresh session.
- Evidence is redacted.
- Impact is real and tied to the program's business data or account security.
- No customer or third-party data was accessed.

If no strong lead appears in 60-90 minutes, switch target app or capture deeper authenticated flows.
