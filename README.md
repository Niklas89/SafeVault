# SafeVault — Activity 1

A runnable .NET 10 Razor Pages application with NUnit security tests.

## Project background

SafeVault is an educational web application intended to manage sensitive information, including user credentials and financial records. The scenario places you in the role of lead developer responsible for protecting the application against common attacks while preserving data integrity.

This project implements the first of three security activities. Activity 1 focuses on secure input handling, SQL injection prevention, and cross-site scripting (XSS) prevention. The current application accepts a username and email through a web form and stores validated submissions in a database. It establishes the foundation for authentication and authorization in Activity 2; it does not yet implement credential or financial-record management.

## Activity instructions

The assignment asks you to generate secure application code and tests that simulate attacks, starting from these supplied examples:

- A `webform.html` form that posts username and email fields to `/submit`.
- A `database.sql` schema defining a `Users` table with an auto-incrementing `UserID`, `Username`, and `Email`, with both text fields limited to 100 characters.
- An NUnit test fixture, `Tests/TestInputValidation.cs`, containing placeholder `TestForSQLInjection` and `TestForXSS` tests.

The required steps are:

1. **Review the scenario.** Identify the need to validate user input, secure database queries, and test resistance to SQL injection and XSS.
2. **Generate input-validation code.** Sanitize username and email input, remove malicious characters as described in the assignment, and ensure data integrity so harmful scripts or query fragments are not accepted. This implementation trims surrounding whitespace and rejects malformed values instead of deleting characters from them, which could silently change their meaning. HTML output encoding provides a separate defense against XSS.
3. **Use parameterized queries.** Keep user-provided values separate from SQL statements through placeholders and bound parameters. Include a secure query for retrieving user information. This application implements parameterized user insertion and username lookup; login functionality is reserved for a later activity.
4. **Test for vulnerabilities.** Write and run NUnit tests using SQL injection attempts and malicious script inputs. Verify that invalid submissions are rejected, query payloads cannot alter SQL behavior, displayed values are encoded, and existing data remains intact.
5. **Save the work.** Keep the secure application code and test cases in the sandbox so they can be extended with authentication and authorization in Activity 2.

The expected deliverables are working input-validation and parameterized-query code, tests demonstrating protection against the simulated SQL injection and XSS attacks, and saved source files ready for the next activity. The sections below explain how to run this implementation, its security choices, and the completed tests.

## Run

```powershell
dotnet restore SafeVault.slnx
dotnet test SafeVault.slnx
dotnet run --project SafeVault --urls http://localhost:5080
```

Open http://localhost:5080/submit. Requires the .NET 10 SDK and NuGet access for the initial restore. SQLite creates `SafeVault/App_Data/safevault.db` automatically. Tests use separate in-memory databases and do not change application data.

## Security decisions

- Server-side validation trims surrounding whitespace and rejects malformed values. Silently removing attack characters could change account identities. Usernames allow 3–100 ASCII letters, digits, underscores, dots and hyphens, beginning with a letter, digit or underscore.
- Email supports a deliberately restricted ordinary ASCII format, including plus tags and apostrophes; it is not a complete international email validator or proof of mailbox ownership. Both fields are limited to 100 characters.
- INSERT and SELECT use bound, explicitly typed parameters. Search payloads are sent directly to the repository in tests, demonstrating protection independent of input validation.
- Razor encodes displayed values in HTML text. Do not use Html.Raw for user data or embed values directly into JavaScript. A restrictive Content Security Policy provides an additional layer.
- Razor Pages antiforgery tokens protect POST submissions. Database constraints prevent duplicate usernames and null/oversized stored values. Error responses do not expose SQL details.
- SQLite replaces the supplied MySQL AUTO_INCREMENT schema so this sandbox needs no database server. The equivalent SQLite schema is in database.sql and initialized by UserRepository.

## Tests

### Manual checks after a successful submission

The **Saved** message means the valid submission was stored in the application database. Keep the app running and use [the SafeVault form](http://localhost:5080/submit) to try these checks:

| Test | What to enter | Expected result |
| --- | --- | --- |
| Duplicate username | Submit the same username again with a valid email | A message asking you to choose another username |
| New valid user | `test_user2` / `test2@example.com` (use an unused username) | A Saved message |
| Invalid email | `test_user3` / `invalid-email` | The browser blocks submission |
| SQL injection | Username: `' OR 1=1 --`, with a valid email | Submission is blocked or rejected |
| XSS | Username: `<script>alert(1)</script>`, with a valid email | Submission is blocked or rejected; no JavaScript alert appears |

Browser validation may stop invalid input before it reaches the server. These manual checks alone do not verify the server or database protections.

### Run the automated security tests

Open a second terminal in the project root (the folder containing `SafeVault.slnx`) and run:

```powershell
dotnet test SafeVault.slnx
```

The current suite should report **35 passed, 0 failed**. It sends attack inputs directly to the application and database queries, bypassing browser validation, and checks that existing data remains intact. Tests use isolated in-memory databases, so users saved through the running application remain unchanged.


NUnit covers normalization, field boundaries, malformed emails, SQL injection payloads, script/event-handler/encoded XSS inputs, legitimate apostrophes, database integrity after rejected submissions, actual Razor output encoding, missing CSRF tokens, and duplicate users. HTTP tests host the real application with WebApplicationFactory; database tests execute real SQLite queries.

This is the Activity 1 foundation. Authentication, authorization, credential storage and financial-record access are intentionally left for later activities. Run locally with synthetic data; production deployment requires HTTPS and appropriate access controls. No public user lookup endpoint is exposed before authorization exists.

Reference: https://learn.microsoft.com/en-us/aspnet/core/security/cross-site-scripting?view=aspnetcore-10.0

Verified on 2026-09-23: all 35 NUnit tests passed (0 failures, 0 skipped). The final restore/build emitted no warnings. SQLitePCLRaw.bundle_e_sqlite3 is explicitly pinned to 3.0.5 to replace the older vulnerable native SQLite dependency.



