## What changed

<!-- One or two sentences. -->

## Security checklist

<!-- The point of this section is not the ticks. It is that a developer reads
     the questions before a reviewer does. Keep it short enough to be read. -->

- [ ] No new secrets, tokens or credentials in the diff (push protection is a
      backstop, not a review)
- [ ] New dependencies are pinned and were checked for advisories
- [ ] User-controlled input reaching a query, a shell, a file path or a URL is
      parameterised or validated against an allowlist
- [ ] Existing code scanning alerts on the touched files are addressed, not
      inherited
- [ ] If this PR dismisses an alert, the comment names a reason and a ticket

## Security review required?

Tick if any apply — these route to the security team via CODEOWNERS anyway,
but flagging it early saves a round trip.

- [ ] Changes to authentication, authorisation, session handling or crypto
- [ ] Changes under `.github/workflows/`, `.github/codeql/` or `policy/`
- [ ] New outbound network calls, or a new external dependency
- [ ] Changes to how data is stored, logged or exported
