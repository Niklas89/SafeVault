# Activity 3 — Security review and fixes

## Scope and approach

Reviewed application SQL, validation, Razor HTML text and attribute output, authentication cookies, authorization, submission ownership, and dependency advisories. Added attack tests to the existing NUnit suite. Tests use isolated in-memory databases, not the user's saved data.

The activity asked for insecure SQL concatenation and unsanitized output to be identified and corrected **if present**. Neither pattern was found in the reviewed application paths. Existing protections were retained and tested rather than replaced with unnecessary character stripping.

## Findings

| Area | Evidence | Result / action |
| --- | --- | --- |
| SQL injection | All repository values are passed as bound parameters. Schema statements and query selection use fixed SQL, not concatenated input. | Existing protection verified. Added account-lookup payload tests for tautologies, stacked statements, and UNION attempts. |
| Form validation | Registration and submissions validate usernames/email server-side. Passwords are validated separately and hashed, not interpreted as SQL or HTML. | Existing protection retained. Added malicious username/email tests that verify no records are created. |
| Reflected and stored XSS | Razor encodes values in quoted form attributes and table cells. No Html.Raw, raw HTML strings, or JavaScript output sinks were found in application pages. | Existing protection verified with attribute-breakout, SVG, image-handler, and encoded payloads. Historical database values are also tested independently of validation. |
| Stale role/account sessions | Before the fix, an admin ticket still returned HTTP 200 from `/Admin` after the account was demoted or deleted. Both reproduction tests failed. | Fixed: cookie validation checks current account existence, ID, and role on requests processed by authentication. A mismatch rejects the ticket, clears the cookie, and requires login for protected pages. |
| Ownership referential integrity | A repository constructed with `Foreign Keys=False` could save an entry pointing to a nonexistent owner. The rollback test failed before the fix. The normal application configuration already enabled foreign keys. | Defense-in-depth fix: the repository forces foreign-key enforcement for every connection. Invalid ownership fails, and the transaction rolls back the new entry. |
| Dependencies | `dotnet list SafeVault.slnx package --vulnerable --include-transitive` checked the configured advisory sources. | No known vulnerable direct or transitive packages reported for either project at review time. This is not a guarantee against undisclosed vulnerabilities. |

## Changes saved

- `SafeVault/Program.cs`: revalidate session account identity and role before authorization.
- `SafeVault/UserRepository.cs`: enforce SQLite foreign keys at the repository boundary.
- `Tests/SecurityAuditTests.cs`: 14 new regression cases using the existing authentication test fixture.
- `Tests/AuthenticationTests.cs`: make the fixture partial so the Activity 3 cases share its isolated setup.
- `README.md`: Activity 3 instructions and updated security behavior.

The registration form still retains entered fields after errors, as requested. Razor encodes the values, passwords remain masked in the form, and responses use `no-store`. Passwords are nevertheless present in that response's HTML; masking is not encryption. They are not added to logs, session state, or plaintext database columns by this implementation.

## Verification

Before the fixes, all three targeted reproduction cases failed: demoted admin, deleted admin, and invalid ownership with foreign keys disabled. After the fixes, the complete suite passed: **82 passed, 0 failed, 0 skipped**. The Release publish also succeeded with no warnings shown and produced `.artifacts/activity3/publish`. No deployment was performed.

Run the complete suite from the project root:

```powershell
dotnet test SafeVault.slnx --artifacts-path .artifacts/activity3
dotnet list SafeVault.slnx package --vulnerable --include-transitive
```

## Recommendations and deployment scope

Continue using parameters for every SQL value. If future features allow user-selected sorting or table names, map them to a fixed allowlist; SQL identifiers cannot be protected by ordinary value parameters. Continue using Razor output encoding for HTML. Validation alone does not protect every output context, and adding Html.Raw or inserting user input into scripts would require a separate review. These practices follow the [OWASP SQL injection guidance](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html) and [OWASP XSS guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html).

This review verifies the covered source paths and attack cases, not an entire deployed environment. Before deploying, use the Production environment with HTTPS and appropriately protected database files and persistent data-protection keys. The local launch profile intentionally selects Development and permits HTTP. Review trusted reverse-proxy configuration if hosting behind one; the current limiter uses the direct client IP and is single-process. No live deployment or browser penetration scan was performed.

Remaining scope limits include MFA, password reset, distributed/account-based throttling, and revocation of a copied session cookie on logout or password change. Logout clears the browser cookie, but a copied ticket can remain valid until its 20-minute expiration when the account identity and role are unchanged. Account deletion or a role change now invalidates that ticket on its next authenticated request. These limits must be assessed against the intended deployment rather than treating passing tests as a blanket security certification.

