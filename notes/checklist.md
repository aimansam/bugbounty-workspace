# Testing Checklist

## Before Testing

- Confirm the asset is in scope.
- Confirm the testing method is allowed.
- Create a program folder with `scripts/core/new-program.sh <program-name>`.
- Save policy notes in `scope.md`.

## Recon

- Review DNS records.
- Review HTTP headers.
- Identify technologies and frameworks.
- Check public docs, changelogs, and API references.
- Search for exposed development or staging assets.

## Web App Testing

- Map unauthenticated routes.
- Map authenticated routes by role.
- Test authorization boundaries.
- Test object IDs and tenant boundaries.
- Test file upload validation.
- Test redirects and callback parameters.
- Test input reflection and stored rendering.
- Test password reset and email change flows.

## API Testing

- Collect endpoints from the frontend and docs.
- Check method confusion.
- Check missing object-level authorization.
- Check mass assignment.
- Check rate limits where allowed.
- Check error messages for sensitive details.

## Reporting

- Keep reproduction steps short and deterministic.
- Include impact in business terms.
- Include only necessary evidence.
- Mention constraints and assumptions.
