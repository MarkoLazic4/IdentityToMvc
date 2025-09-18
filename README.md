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
- [.NET SDK 8.x]
- Visual Studio 2022 (recommended) or VS Code + C# extension  
- SQL Server / LocalDB ili SQLite (any EF Core-supported database)  
- (Optional) SMTP server for email sending (Mailtrap, Papercut, or real SMTP)

---

## Quick Start (local)

1. **Clone the repository**
```bash
git clone https://github.com/MarkoLa0000/IdentityToMvc.git
cd IdentityToMvc

````

2. **Open the solution in Visual Studio / VS Code**

3. **Configure appsettings.Local.json or use user-secrets**

4. **Create and apply migrations**

```bash
cd src/IdentityToMvc.Web
dotnet ef migrations add InitialIdentitySchema -o Data/Migrations
dotnet ef database update
```

**OR (Visual Studio — Package Manager Console)**

```powershell
Add-Migration InitialIdentitySchema -OutputDir Data/Migrations
Update-Database
```
5. **Run the application**
   
# License & Contact

* **License:** MIT
* **GitHub:** [@MarkoLa0000](https://github.com/MarkoLa0000)

