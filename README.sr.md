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
- [.NET SDK 8.x]
- Visual Studio 2022 (preporučeno) ili VS Code + C# extension  
- SQL Server / LocalDB ili SQLite (ili bilo koji DB koji podržava EF Core)  
- (Opcionalno) SMTP server za slanje mailova (Mailtrap, Papercut ili pravi SMTP)

---

## Brzi start (lokalno)

1. **Kloniraj repozitorijum**
```bash
git clone https://github.com/<tvoj-username>/IdentityToMvc.git
cd IdentityToMvc

````

2. **Otvori rešenje u Visual Studio / VS Code**

3. **Konfiguriši appsettings.Local.json ili koristi user-secrets**

4. **Kreiraj i primeni migracije**

```bash
cd src/IdentityToMvc.Web
dotnet ef migrations add InitialIdentitySchema -o Data/Migrations
dotnet ef database update
```

**ILI (Visual Studio — Package Manager Console)**

```powershell
Add-Migration InitialIdentitySchema -OutputDir Data/Migrations
Update-Database
```
5. **Pokreni aplikaciju**
   
# Licenca & Kontakt

* **Licenca:** MIT
* **GitHub:** [@MarkoLa0000](https://github.com/MarkoLa0000)
