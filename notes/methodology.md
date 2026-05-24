# Bug Bounty Methodology

## 1. Program Review

- Read the policy carefully.
- Identify allowed and forbidden testing types.
- Record scope before touching anything.

## 2. Passive Recon

- Subdomain discovery from public sources.
- Search engine and certificate transparency review.
- Technology fingerprinting from public responses.
- Public code and documentation review.

## 3. Triage Targets

Prioritize assets with:

- Login or account flows
- File upload or import features
- Payment, billing, or subscription flows
- Admin panels or role boundaries
- API endpoints
- Legacy or unusual technology

## 4. Active Testing

Only test actively when permitted. Start gently and keep logs.

Common areas:

- Access control and IDOR
- Authentication and session handling
- Business logic flaws
- Server-side request forgery
- Cross-site scripting
- Open redirects with impact
- Insecure file upload
- API authorization gaps

## 5. Reporting

A strong report has clear impact, reliable reproduction steps, and minimal but sufficient evidence.
