---
description: "Use when: starting a new authorized bug bounty scope with this workspace automation"
---

# New Scope Hunt

Help me start a new authorized bug bounty program using this workspace.

Inputs I will provide:

- Program name:
- Scope/rules:
- In-scope targets:
- Out-of-scope targets:
- Whether active testing is allowed:
- Whether I have Burp exports:

Follow this workflow:

1. Create or update `programs/<program>/` using `scripts/core/new-program.sh` or the existing templates.
2. Save scope/rules in `scope.md`, targets in `targets.txt`, and exclusions in `out-of-scope.txt` when provided.
3. Recommend the safest first automation command.
4. If broader passive recon is allowed, suggest `--passive-plus` and mention optional tool requirements.
5. If active testing is allowed, suggest the `--active` command with a conservative delay.
6. If Burp exports exist, suggest the `--with-burp` command and the expected folder path.
7. After scripts run, summarize only reportable leads and clearly separate low-value/no-signal results.
8. Keep program data local and do not suggest committing `programs/<program>/` to GitHub.

Default command pattern:

```bash
python3 scripts/core/hunt-automate.py <program> --delay 2
```

Active allowed:

```bash
python3 scripts/core/hunt-automate.py <program> --active --delay 2
```

Broader passive recon allowed:

```bash
python3 scripts/core/hunt-automate.py <program> --passive-plus --delay 2
```

With Burp exports:

```bash
python3 scripts/core/hunt-automate.py <program> --with-burp --delay 2
```

Closeout:

```bash
python3 scripts/core/hunt-automate.py <program> --archive-only
```

Closeout, replace old archives, and remove local program files after archive creation:

```bash
python3 scripts/core/hunt-automate.py <program> --archive-only --replace-archive --purge-after-archive
```

Continue later from the latest archive:

```bash
python3 scripts/core/hunt-automate.py <program> --restore-archive
```
