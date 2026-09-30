# IdentityToMvc

ASP.NET Core 10 MVC application created from the
[TEMPLATE_NAME](TEMPLATE_REPO_URL) template.

## Included account features

- Registration with email confirmation, login and logout, "forgot password", lockout after 3 failed attempts, password change
<!--#if (Profile) -->
- Profile page (phone number)
<!--#endif -->
<!--#if (EmailChange) -->
- Email change (confirmation link to the new address, warning to the old one)
<!--#endif -->
<!--#if (PersonalData) -->
- Personal data download and account deletion (GDPR)
<!--#endif -->
<!--#if (UnlockLink) -->
- Unlock link in the "account locked" email
<!--#endif -->
<!--#if (BreachedPasswords) -->
- Breached password check (Have I Been Pwned, k-anonymity)
<!--#endif -->
<!--#if (TwoFactor) -->
- Two-factor authentication with an authenticator app and recovery codes (secrets encrypted in the database)
<!--#endif -->
<!--#if (Sudo) -->
- Sudo mode: the password is asked again before sensitive changes
<!--#endif -->
<!--#if (Passkeys) -->
- Passkeys (fingerprint, face or device PIN)
<!--#endif -->
<!--#if (Google) -->
- Google login (set `GoogleClientId` / `GoogleClientSecret`)
<!--#endif -->
<!--#if (Facebook) -->
- Facebook login (set `FacebookAppId` / `FacebookAppSecret`)
<!--#endif -->
<!--#if (Notifications) -->
- Security notification emails (password changed, new device, ...)
<!--#endif -->
<!--#if (Devices) -->
- Devices page: every signed-in device, sign out one or all
<!--#endif -->
<!--#if (Activity) -->
- Security activity page
<!--#endif -->
<!--#if (Admin) -->
- Admin panel at `/Admin`: users, roles, audit log
<!--#endif -->
<!--#if (LangBoth) -->
- Serbian (Latin) and English, with a language switch
<!--#elif (LangSr) -->
- Serbian (Latin) user interface
<!--#else -->
- English user interface
<!--#endif -->

Always on: security headers with CSP, `__Host-` cookies, PBKDF2 with 600,000 iterations, no account
enumeration (same answers and timing), pre-account-takeover protection, rate limiting and an audit log
in the database.

## Getting started

1. Set up email in `IdentityToMvc.Web/appsettings.json` (`SMTP` section) or, better, in user secrets /
   `appsettings.Local.json`. In Development the registration page also shows the confirmation link,
   so you can try everything without an SMTP server.
<!--#if (DbSqlServer) -->
2. Check the connection string in `IdentityToMvc.Web/appsettings.Development.json` (SQL Server LocalDB by default).
<!--#elif (DbPostgres) -->
2. Check the connection string in `IdentityToMvc.Web/appsettings.Development.json` (PostgreSQL on localhost by default).
<!--#else -->
2. The SQLite database file is created next to the app (`IdentityToMvc.Web/appsettings.Development.json`).
<!--#endif -->
3. Run it:

   ```bash
   cd IdentityToMvc.Web
   dotnet run
   ```

   In Development the database is created/upgraded automatically from `Data/Migrations`.
<!--#if (Admin) -->
4. To become an administrator put your email into `Admin:Emails` in `appsettings.json`, register and confirm the email.
<!--#endif -->

## Production

- Put the connection string in the environment (`ConnectionStrings__Default`) or a secret store, never in the repository.
- Apply migrations as part of the deployment: `dotnet ef database update` (or `dotnet ef migrations script`).
- Set `Security:DataProtectionCertificatePath` so the keys that protect cookies and tokens are encrypted.
- Behind a reverse proxy, list its IP in `Security:KnownProxies`.
<!--#if (Tests) -->

## Tests

```bash
dotnet test --project IdentityToMvc.Tests
```

The tests run the whole app in memory with SQLite and a fake mailbox.
<!--#endif -->
<!--#if (LangSr) -->

## Translations

Texts are written in English in the code (`L["..."]`, `_t["..."]`) and translated in
`IdentityToMvc.Web/Resources/SharedResource.sr-Latn.resx`. `python3 tools/extract_keys.py` lists texts without a translation.
<!--#endif -->

A detailed guide (in Serbian) explains every feature and setting:
TEMPLATE_REPO_URL/blob/master/docs/UPUTSTVO.md
