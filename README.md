# IdentityToMvc

Migration of **ASP.NET Core Identity** from Razor Pages to **MVC architecture**.  
This project demonstrates how to translate the standard Identity RCL Pages into MVC controllers and views.

---

## Features
- **Auth**: registration, login/logout, external providers, email confirmation  
- **Security**: password reset, 2FA with QR code, recovery codes, lockout after 3 failed attempts, 2FA enforced for external logins too  
- **Profile**: change password/email/personal data, external logins, delete account  
- **Devices & activity**: every signed-in device is listed and can be signed out individually; a security activity timeline shows logins, failed attempts and account changes; an email is sent when a new device signs in  
- **Admin panel** (`/Admin`): dashboard, user search, user details (lock/unlock, sign out everywhere, reset 2FA, confirm email, roles, delete), role management and the full audit log  
- **Localization**: Serbian (Latin) and English, picked from the browser language or the SR/EN switch; emails, validation and Identity error messages are translated too  
- **UI**: Bootstrap 5.3 + Bootstrap Icons, light/dark theme, password strength meter and show/hide toggle, responsive layout  
- **Tests & CI**: integration tests (`IdentityToMvc.Tests`) run the whole app in memory; GitHub Actions builds, tests and checks translations on every push  

| Home | Log in |
|------|--------|
| ![Home](docs/screenshots/home.png) | ![Log in](docs/screenshots/login.png) |

| Authenticator setup | Two-factor settings (dark) |
|---------------------|----------------------------|
| ![Authenticator setup](docs/screenshots/enable-authenticator.png) | ![Two-factor settings](docs/screenshots/two-factor-dark.png) |

| Admin dashboard | Admin: user details |
|-----------------|---------------------|
| ![Admin dashboard](docs/screenshots/admin-dashboard.png) | ![User details](docs/screenshots/admin-user.png) |

| Your devices | Security activity |
|--------------|-------------------|
| ![Devices](docs/screenshots/devices.png) | ![Activity](docs/screenshots/activity.png) |
  
> 📘 **Detailed guide (Serbian)** - how everything works, which parts to reuse for which feature and how to switch features on/off: [docs/UPUTSTVO.md](docs/UPUTSTVO.md)

---

## Use it as a template

This repository is also a `dotnet new` template: every new app starts with the whole account system, renamed to your
app, with only the features you pick.

```bash
git clone https://github.com/MarkoLazic4/IdentityToMvc.git
dotnet new install ./IdentityToMvc            # once (later: dotnet new install IdentityToMvc.Templates)

dotnet new identitymvc -n Tool   --tier basic --lang sr
dotnet new identitymvc -n Shop   --tier standard --google --db postgres
dotnet new identitymvc -n Clinic --tier full --lang both
dotnet new identitymvc -n Portal --tier basic --admin --personal-data --tests
```

| Package | What you get |
|---------|--------------|
| `--tier basic` | Registration, email confirmation, login, forgot password, lockout, password change |
| `--tier standard` (default) | basic + 2FA, devices, security activity, email change, personal data, security emails, breached-password check, sudo mode, unlock link, tests |
| `--tier full` | standard + passkeys and the admin panel |

Feature switches add to any package: `--profile --email-change --personal-data --unlock-link --breached-passwords
--two-factor --sudo --passkeys --google --facebook --notifications --devices --activity --admin --tests`.
`--db sqlserver|postgres|sqlite` (migrations included, applied automatically in Development) and `--lang both|sr|en`.

**Add a feature later** - copies the feature's files into an existing app and writes `ADD-<feature>.md` with the code
to add to the shared files (run it in the solution folder with the options the app was created with):

```bash
dotnet new identitymvc-add --feature admin -n Portal --tier basic --personal-data --tests
```

**Package / publish:** `dotnet pack templates/IdentityToMvc.Templates.csproj -o artifacts` builds a NuGet template package
with both templates; pushing it to nuget.org or a private feed is a separate step (see the guide, section 7).

---

## Security

On top of ASP.NET Core Identity's defaults the app adds:

| Area | What it does |
|------|--------------|
| **Passkeys (WebAuthn)** | Passwordless, phishing-resistant login with Face ID / Touch ID / Windows Hello / security keys (.NET 10 Identity passkeys, schema v3). Passkey autofill in the email field, user verification required. Manage them under *Manage account &rarr; Passkeys*. |
| **Sudo mode** | Sensitive changes (2FA, recovery codes, email, external logins, passkeys, personal data download) require the password again if the last authentication was more than 15 minutes ago. |
| **Lockout** | 3 failed attempts lock the account for 10 minutes (login, 2FA codes, "confirm it's you", delete account). |
| **Rate limiting** | Per-IP limits on account form posts (20/min) and on endpoints that send email (5 per 10 min), `429` with `Retry-After`. |
| **Password policy** | 8+ characters with upper/lowercase, digit and symbol; must not contain the email; checked against the [Have I Been Pwned](https://haveibeenpwned.com/Passwords) breach corpus using k-anonymity (only 5 hash characters leave the server, fails open if the API is down). |
| **Password hashing** | PBKDF2-HMAC-SHA512 with 600,000 iterations; older hashes are upgraded on the next login. |
| **Sessions** | Every sign-in is a server-side session: users see their devices and can end any of them (effective immediately), "sign out everywhere", security stamp re-validated every 5 minutes, password/2FA changes end other sessions while keeping the current one. New-device sign-in email. |
| **Security notifications** | Email + audit log stored in the database (`SecurityEvents`) and in the app log (`Security audit: <Event>`) for logins, failed attempts, password/email/2FA/passkey/login-method changes, lockouts, admin actions and account deletion. Old entries are removed automatically. |
| **No user enumeration** | Register, resend confirmation, forgot/reset password answer the same way for unknown accounts; emails are sent from a background queue, and login takes the same time whether the account exists or not. |
| **Pre-account takeover** | Registering an already confirmed email only emails the owner; an unconfirmed account can't "reserve" an address (a new registration replaces it); external logins never auto-link to an existing account. |
| **Lockout abuse** | A locked-out owner gets an unlock link by email and can still sign in with a passkey, so strangers can't keep an account locked. Accounts locked by an administrator stay locked. |
| **Secrets at rest** | Authenticator (TOTP) keys are encrypted and recovery codes are stored only as PBKDF2 hashes; Data Protection keys can be encrypted with a certificate. |
| **Admin panel** | Only for the `Admin` role, and only after the admin has set up 2FA or a passkey. Admins can't lock or demote themselves or delete the last admin; every admin action is audited. |
| **Cookies** | `__Host-` prefixed, `Secure`, `HttpOnly`; antiforgery cookie `SameSite=Strict`. |
| **Headers** | Content-Security-Policy with per-request nonces (no inline scripts), HSTS (1 year), `X-Frame-Options`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP, no `Server` header, `no-store` on account pages. |
| **Tokens & keys** | Email/reset links expire after 3 hours; Data Protection keys are stored in the database so tokens and cookies survive restarts and work across instances. |

Configuration (`Security` section in `appsettings.json`):

```json
"Security": {
  "EnableTwoFactor": true,
  "EnablePasskeys": true,
  "RequireRecentAuthentication": true,
  "EnableRateLimiting": true,
  "CheckBreachedPasswords": true,
  "SendSecurityNotifications": true,
  "MaxPasskeysPerUser": 10,
  "PasskeyServerDomain": "",      // e.g. "example.com" - defaults to the request host
  "KnownProxies": [],             // reverse proxy IPs trusted for X-Forwarded-For/Proto
  "RequireTwoFactorForAdmins": true,
  "AuditRetentionDays": 365,
  "SessionRetentionDays": 30,
  "DataProtectionCertificatePath": "",     // .pfx that encrypts the Data Protection keys (recommended in production)
  "DataProtectionCertificatePassword": ""
},
"Admin": {
  "Emails": [ "you@example.com" ]  // become administrators once the address is confirmed
},
"Localization": {
  "DefaultCulture": "sr-Latn-RS"  // or "en"; used when the browser asks for neither language
}
```

> Passkeys require HTTPS (or `localhost`). The included migrations create the passkeys, Data Protection keys,
> `SecurityEvents` and `UserSessions` tables.

![Passkeys](docs/screenshots/passkeys.png)

---

## Prerequisites
- [.NET SDK 10.x](https://dotnet.microsoft.com/download/dotnet/10.0)
- Visual Studio 2026 (recommended) or VS Code + C# Dev Kit  
- SQL Server / LocalDB / SQL Express (or PostgreSQL / SQLite for apps made with the template)  
- `dotnet-ef` tool: `dotnet tool install --global dotnet-ef`  
- (Optional) SMTP server for email sending (Mailtrap, Papercut, or real SMTP)

---

## Quick Start (local)

1. **Clone the repository**
```bash
git clone https://github.com/MarkoLazic4/IdentityToMvc.git
cd IdentityToMvc
```

2. **Open the solution in Visual Studio / VS Code**

3. **Configure appsettings.Local.json or use user-secrets**

`appsettings.Local.json` (listed in `.gitignore`) overrides `appsettings.json`:

```json
{
  "ConnectionStrings": {
    "Default": "Server=(localdb)\\MSSQLLocalDB;Database=IdentityToMvc;Trusted_Connection=True;TrustServerCertificate=True"
  },
  "SMTP": {
    "Host": "smtp.example.com",
    "Port": 587,
    "EnableSsl": true,
    "Username": "user@example.com",
    "Password": "your-password",
    "From": "no-reply@example.com",
    "FromName": "IdentityToMvc"
  },
  "GoogleClientId": "...",
  "GoogleClientSecret": "...",
  "FacebookAppId": "...",
  "FacebookAppSecret": "..."
}
```

4. **Database** - the migrations are included (`Data/Migrations/SqlServer`) and in the `Development` environment the
   app creates/upgrades the database on startup. Elsewhere apply them with `dotnet ef database update`.
   *Upgrading from an older version where you created your own migrations? Delete them (and the local database).*

5. **Run the application**

```bash
dotnet run
```

In the `Development` environment the registration confirmation page shows the email confirmation link directly, so you can test without an SMTP server.

6. **Become an administrator** - put your email into `Admin:Emails`, register (or restart the app if the
   account already exists) and confirm the email. Set up two-factor authentication or a passkey, then open
   *Admin panel* from the user menu.

---

## Tests

```bash
dotnet test --project IdentityToMvc.Tests
```

The tests start the real application in memory with an SQLite database and a fake mailbox - no SQL Server or
SMTP needed. They cover registration, account takeover protections, lockout and the unlock link, secrets at
rest, device sessions, the admin panel, security headers and localization.

## Translations

Texts are written in English in the code (`L["..."]` in views, `_t["..."]` in controllers) and translated in
`IdentityToMvc.Web/Resources/SharedResource.sr-Latn.resx`. After adding or changing a text, run

```bash
python3 tools/extract_keys.py
```

It lists every text that has no Serbian translation yet (CI fails while any are missing).

# License & Contact

* **License:** MIT
* **GitHub:** [@MarkoLazic](https://github.com/MarkoLazic4)

