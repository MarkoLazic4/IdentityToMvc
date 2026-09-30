# IdentityToMvc

Migracija **ASP.NET Core Identity** iz Razor Pages u **MVC arhitekturu**.  
Projekat prikazuje kako prevesti standardne Identity RCL stranice u MVC controllere i view-e.

---

## Funkcionalnosti
- **Auth**: registracija, login/logout, eksterni provideri, potvrda email-a  
- **Bezbednost**: reset lozinke, 2FA, recovery kodovi  
- **Profil**: izmena lozinke/email-a/podataka, spoljašnji nalozi, brisanje podataka  
  
---

## Preduslovi
- [.NET SDK 10.x](https://dotnet.microsoft.com/download/dotnet/10.0)
- Visual Studio 2026 (preporučeno) ili VS Code + C# Dev Kit  
- SQL Server / LocalDB / SQL Express  
- `dotnet-ef` alat: `dotnet tool install --global dotnet-ef`  
- (Opcionalno) SMTP server za slanje mailova (Mailtrap, Papercut ili pravi SMTP)

---

## Brzi start (lokalno)

1. **Kloniraj repozitorijum**
```bash
git clone https://github.com/MarkoLazic4/IdentityToMvc.git
cd IdentityToMvc
```

2. **Otvori rešenje u Visual Studio / VS Code**

3. **Konfiguriši appsettings.Local.json ili koristi user-secrets**

`appsettings.Local.json` (naveden u `.gitignore`) ima prednost nad `appsettings.json`:

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
    "Password": "tvoja-lozinka"
  },
  "GoogleClientId": "...",
  "GoogleClientSecret": "...",
  "FacebookAppId": "...",
  "FacebookAppSecret": "..."
}
```

4. **Kreiraj i primeni migracije**

```bash
cd IdentityToMvc.Web
dotnet ef migrations add InitialIdentitySchema -o Data/Migrations
dotnet ef database update
```

**ILI (Visual Studio — Package Manager Console)**

```powershell
Add-Migration InitialIdentitySchema -OutputDir Data/Migrations
Update-Database
```
5. **Pokreni aplikaciju**

```bash
dotnet run
```

U `Development` okruženju stranica za potvrdu registracije direktno prikazuje link za potvrdu email-a, pa možeš da testiraš i bez SMTP servera.

# Licenca & Kontakt

* **Licenca:** MIT
* **GitHub:** [@MarkoLazic](https://github.com/MarkoLazic4)
