# SafeVault — Activities 1 and 2

A runnable .NET 10 Razor Pages application with NUnit security tests.

## Project background

SafeVault is an educational web application intended to manage sensitive information, including user credentials and financial records. The scenario places you in the role of lead developer responsible for protecting the application against common attacks while preserving data integrity.

This project implements the first two of three security activities. Activity 1 establishes input validation, parameterized database queries, and XSS defenses. Activity 2 adds account registration, password authentication, session cookies, and authorization for user and admin roles. Financial-record management is not implemented; Activity 3 will further debug and harden these security layers.

## Activity 1 instructions

The assignment asks you to generate secure application code and tests that simulate attacks, starting from these supplied examples:

- A `webform.html` form that posts username and email fields to `/submit`.
- A `database.sql` schema defining a `Users` table with an auto-incrementing `UserID`, `Username`, and `Email`, with both text fields limited to 100 characters.
- An NUnit test fixture, `Tests/TestInputValidation.cs`, containing placeholder `TestForSQLInjection` and `TestForXSS` tests.

The required steps are:

1. **Review the scenario.** Identify the need to validate user input, secure database queries, and test resistance to SQL injection and XSS.
2. **Generate input-validation code.** Sanitize username and email input, remove malicious characters as described in the assignment, and ensure data integrity so harmful scripts or query fragments are not accepted. This implementation trims surrounding whitespace and rejects malformed values instead of deleting characters from them, which could silently change their meaning. HTML output encoding provides a separate defense against XSS.
3. **Use parameterized queries.** Keep user-provided values separate from SQL statements through placeholders and bound parameters. Include a secure query for retrieving user information. This application implements parameterized user insertion and username lookup; Activity 2 adds login below.
4. **Test for vulnerabilities.** Write and run NUnit tests using SQL injection attempts and malicious script inputs. Verify that invalid submissions are rejected, query payloads cannot alter SQL behavior, displayed values are encoded, and existing data remains intact.
5. **Save the work.** Keep the secure application code and test cases in the sandbox so they can be extended with authentication and authorization in Activity 2.

The expected deliverables are working input-validation and parameterized-query code, tests demonstrating protection against the simulated SQL injection and XSS attacks, and saved source files ready for the next activity. The sections below explain how to run this implementation, its security choices, and the completed tests.

## Run

```powershell
dotnet restore SafeVault.slnx
dotnet test SafeVault.slnx
dotnet run --project SafeVault --urls http://localhost:5080
```

Open http://localhost:5080/Register to create a login account, then sign in at http://localhost:5080/Login. The command starts the server; if no browser opens, open the URL manually. Keep the terminal open and press Ctrl+C to stop it. Requires the .NET 10 SDK and NuGet access for the initial restore. SQLite creates `SafeVault/App_Data/safevault.db` automatically. Tests use separate in-memory databases and do not change application data.

## Security decisions

- Server-side validation trims surrounding whitespace and rejects malformed values. Silently removing attack characters could change account identities. Usernames allow 3–100 ASCII letters, digits, underscores, dots and hyphens, beginning with a letter, digit or underscore.
- Email supports a deliberately restricted ordinary ASCII format, including plus tags and apostrophes; it is not a complete international email validator or proof of mailbox ownership. Both fields are limited to 100 characters.
- INSERT and SELECT use bound, explicitly typed parameters. Search payloads are sent directly to the repository in tests, demonstrating protection independent of input validation.
- Razor encodes displayed values in HTML text. Do not use Html.Raw for user data or embed values directly into JavaScript. A restrictive Content Security Policy provides an additional layer.
- Razor Pages antiforgery tokens protect POST submissions. Database constraints prevent duplicate usernames and null/oversized stored values. Error responses do not expose SQL details.
- SQLite replaces the supplied MySQL AUTO_INCREMENT schema so this sandbox needs no database server. The equivalent SQLite schema is in database.sql and initialized by UserRepository.

## Tests

### Manual checks after a successful submission

Sign in before opening `/submit`. This Activity 1 form creates a username/email record, not a login account; use `/Register` to create accounts with passwords. The **Saved** message means the valid submission was stored in the application database. Keep the app running and use [the SafeVault form](http://localhost:5080/submit) to try these checks:

| Test | What to enter | Expected result |
| --- | --- | --- |
| Duplicate username | Submit the same username again with a valid email | A message asking you to choose another username |
| New valid user | `test_user2` / `test2@example.com` (use an unused username) | A Saved message |
| Invalid email | `test_user3` / `invalid-email` | The browser blocks submission |
| SQL injection | Username: `' OR 1=1 --`, with a valid email | Submission is blocked or rejected |
| XSS | Username: `<script>alert(1)</script>`, with a valid email | Submission is blocked or rejected; no JavaScript alert appears |

Browser validation may stop invalid input before it reaches the server. These manual checks alone do not verify the server or database protections.

### Run the automated security tests

Stop the running application with Ctrl+C, then run this from the project root (the folder containing `SafeVault.slnx`). To leave the application running on Windows, use `dotnet test SafeVault.slnx --artifacts-path .artifacts` so the build does not overwrite its locked executable:

```powershell
dotnet test SafeVault.slnx
```

The expanded suite should report **68 passed, 0 failed**: 35 Activity 1 tests and 33 authentication, registration, and listing tests. It sends attack inputs directly to the application and database queries, bypassing browser validation, and checks that existing data remains intact. Tests use isolated in-memory databases, so users saved through the running application remain unchanged.


NUnit covers normalization, field boundaries, malformed emails, SQL injection payloads, script/event-handler/encoded XSS inputs, legitimate apostrophes, database integrity after rejected submissions, actual Razor output encoding, missing CSRF tokens, and duplicate users. HTTP tests host the real application with WebApplicationFactory; database tests execute real SQLite queries.

Use synthetic data for the local exercises. Authentication and role-based authorization are now implemented; financial-record access is outside this activity. The admin-only page lists usernames and email addresses. Password hashes are never displayed.

Reference: https://learn.microsoft.com/en-us/aspnet/core/security/cross-site-scripting?view=aspnetcore-10.0

Activity 1 verification on 2026-09-23: all 35 NUnit tests passed (0 failures, 0 skipped). SQLitePCLRaw.bundle_e_sqlite3 is explicitly pinned to 3.0.5 to replace the older vulnerable native SQLite dependency.




## Activity 2 instructions and implementation

The second activity asks you to protect user accounts on top of the secure coding foundation:

1. Review the need to authenticate legitimate users and restrict sensitive features by role.
2. Implement username/password login and secure password hashing using bcrypt or Argon2.
3. Assign roles such as user and admin and enforce role-based access to an Admin Dashboard.
4. Run tests for invalid logins, unauthorized requests, and access by different roles.
5. Save the implementation and tests for further debugging and hardening in Activity 3.

The implementation uses BCrypt.Net-Next with a random salt and work factor 12. Passwords require at least 12 characters and at most 72 UTF-8 bytes to avoid bcrypt truncation. They are never trimmed or stored in plaintext. Unknown usernames receive a dummy hash comparison and the same error message as an incorrect password.

Public registration always assigns `user`; submitting a role field cannot grant administrator access. Administrator accounts are created only by the trusted local command described below. Queries use bound parameters, and account creation inserts the user and password hash in a single transaction. Startup adds the Accounts table automatically while preserving Activity 1 records. Existing records have no password and cannot log in; register a new, unused username. The old `/submit` form remains an authenticated validation exercise and does not provision credentials.

| Route | Access |
| --- | --- |
| `/Register`, `/Login` | Public, with CSRF protection on POST |
| `/Dashboard`, `/submit` | Any signed-in account |
| `/Admin` | Admin role only; regular users receive HTTP 403 |
| `/Logout` | Signed-in account, POST with a CSRF token |

Anonymous requests to protected pages redirect to login. Successful login goes to a fixed local dashboard, ignoring supplied return URLs. Signed-in users who open or refresh `/Login` are also redirected to `/Dashboard`; a repeated login POST preserves their current session and redirects there as well. The encrypted and authenticated session cookie is HttpOnly, SameSite=Strict, nonpersistent, and expires after 20 minutes without sliding renewal. Production requires Secure cookies and enables HTTPS redirection and HSTS. The Development launch profile allows local HTTP for the exercise; use HTTPS in deployment. Login and registration share a limit of 10 requests per minute per client IP, including form GETs; HTTP 429 means wait a minute before retrying. This is a single-process limiter, not a distributed account lockout system.

### Create an administrator

Stop the running app with Ctrl+C. From the project root, run:

```powershell
dotnet run --project SafeVault -- --create-admin
```

Enter an unused username, email, password and password confirmation when prompted. Password entry is hidden in an interactive terminal. No default admin or password is supplied. This command creates an account and exits without starting the web server; access to the local machine and database is the administrative trust boundary.

Restart the server:

```powershell
dotnet run --project SafeVault --urls http://localhost:5080
```

### Manually test authentication and roles

1. Register an unused username at http://localhost:5080/Register with a valid email and matching password of at least 12 characters. The account should be created.
2. Visit `/Login` and use an incorrect password. Expect `Invalid username or password.` and no access to `/Dashboard`.
3. Sign in with the correct password. Expect your dashboard and access to `/submit`.
4. As this regular user, visit `/Admin` directly. Expect HTTP 403 (the browser may display a blank forbidden response); hiding the dashboard link is not the access control.
5. Click **Sign out** on your dashboard, then visit `/Dashboard` or `/Admin`. Expect a redirect to login.
6. Sign in as the administrator created with the local command. Visit `/Admin` and expect **Admin Dashboard** and **Administrator access granted**.

### Automated Activity 2 coverage

`Tests/AuthenticationTests.cs` uses the real cookie middleware, Razor forms, bcrypt, and isolated SQLite databases. It covers valid and invalid credentials, SQL/script payloads in login, anonymous and role-based access, role escalation attempts at registration, salted hash storage, password limits, legacy records, duplicate registration, CSRF protection, cookie tampering, logout, and rate limiting. Activity 1 HTTP tests now sign in before testing the protected submission form.

This activity does not implement password reset, MFA, email ownership verification, role-management pages, distributed throttling, or server-side revocation of a copied session cookie. Logout removes the browser cookie; a copied ticket remains valid until its 20-minute expiry. Roles in existing tickets reflect the role at login. These are explicit scope limits for the next hardening activity, not claims of production readiness.

References: [ASP.NET Core cookie authentication](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/cookie?view=aspnetcore-10.0), [BCrypt.Net-Next](https://www.nuget.org/packages/BCrypt.Net-Next/4.2.0).


Activity 2 verification (including signed-in login redirects): all 63 tests passed (0 failures, 0 skipped) using dotnet test SafeVault.slnx --artifacts-path .artifacts. The final restore and build emitted no warnings. Existing-database upgrade and production HTTPS session cookies are covered.




## Saved entries and user lists

The Admin Dashboard at `/Admin` lists all rows in Users with username and email, including registered accounts and records entered through `/submit`. It remains restricted to the admin role.

Each signed-in user's `/Dashboard` shows only entries they created through `/submit`, newest first. Ownership comes from the authenticated session, never from a posted field or query parameter. New entries and their ownership records are saved atomically. Displayed values are HTML-encoded.

Startup automatically adds the SubmissionOwners table. Existing records are preserved, but old submissions cannot be attributed to their creators because that information was not previously stored. They appear in the admin list, not in personal dashboards. Registering an account does not count as a saved submission.

To check: sign in, select **Add an entry**, save an unused username and email, and return to your dashboard. The new entry should appear. Sign in as a different account and confirm it does not appear there. Administrators can view the full username/email list at `/Admin`.
