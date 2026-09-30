# IdentityToMvc

Migration of **ASP.NET Core Identity** from Razor Pages to **MVC architecture**.  
This project demonstrates how to translate the standard Identity RCL Pages into MVC controllers and views.

---

## Features
- **Auth**: registration, login/logout, external providers, email confirmation  
- **Security**: password reset, 2FA with QR code, recovery codes, lockout after 3 failed attempts, 2FA enforced for external logins too  
- **Profile**: change password/email/personal data, external logins, delete account  
- **UI**: Bootstrap 5.3 + Bootstrap Icons, light/dark theme, password strength meter and show/hide toggle, responsive layout  

| Home | Log in |
|------|--------|
| ![Home](docs/screenshots/home.png) | ![Log in](docs/screenshots/login.png) |

| Authenticator setup | Two-factor settings (dark) |
|---------------------|----------------------------|
| ![Authenticator setup](docs/screenshots/enable-authenticator.png) | ![Two-factor settings](docs/screenshots/two-factor-dark.png) |
  
> 📘 **Detailed guide (Serbian)** - how everything works, which parts to reuse for which feature and how to switch features on/off: [docs/UPUTSTVO.md](docs/UPUTSTVO.md)

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
| **Sessions** | "Sign out of all other devices", security stamp re-validated every 5 minutes, password/2FA changes end other sessions while keeping the current one. |
| **Security notifications** | Email + structured audit log (`Security audit: <Event>`) for password/email/2FA/passkey/login-method changes, lockouts and account deletion. |
| **No user enumeration** | Register confirmation, resend confirmation, forgot/reset password answer the same way for unknown accounts; emails are sent from a background queue so timing doesn't leak either. |
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
  "KnownProxies": []              // reverse proxy IPs trusted for X-Forwarded-For/Proto
}
```

> Passkeys require HTTPS (or `localhost`). After pulling these changes, create a new migration - the
> schema now includes the passkeys and Data Protection keys tables.

![Passkeys](docs/screenshots/passkeys.png)

---

## Prerequisites
- [.NET SDK 10.x](https://dotnet.microsoft.com/download/dotnet/10.0)
- Visual Studio 2026 (recommended) or VS Code + C# Dev Kit  
- SQL Server / LocalDB / SQL Express  
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

4. **Create and apply migrations**

```bash
cd IdentityToMvc.Web
dotnet ef migrations add InitialIdentitySchema -o Data/Migrations
dotnet ef database update
```

**OR (Visual Studio — Package Manager Console)**

```powershell
Add-Migration InitialIdentitySchema -OutputDir Data/Migrations
Update-Database
```
5. **Run the application**

```bash
dotnet run
```

In the `Development` environment the registration confirmation page shows the email confirmation link directly, so you can test without an SMTP server.

# License & Contact

* **License:** MIT
* **GitHub:** [@MarkoLazic](https://github.com/MarkoLazic4)

