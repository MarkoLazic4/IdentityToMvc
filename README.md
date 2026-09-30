# IdentityToMvc

Migration of **ASP.NET Core Identity** from Razor Pages to **MVC architecture**.  
This project demonstrates how to translate the standard Identity RCL Pages into MVC controllers and views.

---

## Features
- **Auth**: registration, login/logout, external providers, email confirmation  
- **Security**: password reset, 2FA, recovery codes  
- **Profile**: change password/email/personal data, external logins, delete account  
  
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
    "Password": "your-password"
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

