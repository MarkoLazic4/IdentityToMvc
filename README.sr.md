# IdentityToMvc

Migracija **ASP.NET Core Identity** iz Razor Pages u **MVC arhitekturu**.  
Projekat prikazuje kako prevesti standardne Identity RCL stranice u MVC controllere i view-e.

---

## Funkcionalnosti
- **Auth**: registracija, login/logout, eksterni provideri, potvrda email-a  
- **Bezbednost**: reset lozinke, 2FA sa QR kodom, recovery kodovi, zaključavanje naloga posle 3 neuspešna pokušaja, 2FA važi i za eksterne prijave  
- **Profil**: izmena lozinke/email-a/podataka, spoljašnji nalozi, brisanje podataka  
- **UI**: Bootstrap 5.3 + Bootstrap Icons, svetla/tamna tema, indikator jačine lozinke i prikaz/sakrivanje lozinke, responsive layout  

| Početna | Prijava |
|---------|---------|
| ![Početna](docs/screenshots/home.png) | ![Prijava](docs/screenshots/login.png) |

| Podešavanje authenticator-a | 2FA podešavanja (tamna tema) |
|-----------------------------|------------------------------|
| ![Authenticator](docs/screenshots/enable-authenticator.png) | ![2FA](docs/screenshots/two-factor-dark.png) |
  
---

## Bezbednost

Pored podrazumevanih Identity podešavanja, aplikacija dodaje:

| Oblast | Šta radi |
|--------|----------|
| **Passkeys (WebAuthn)** | Prijava bez lozinke, otporna na phishing - Face ID / Touch ID / Windows Hello / sigurnosni ključevi (.NET 10 Identity passkeys, šema v3). Passkey autofill u polju za email, obavezna verifikacija korisnika. Upravljanje u *Manage account &rarr; Passkeys*. |
| **Sudo mode** | Osetljive izmene (2FA, recovery kodovi, email, eksterni nalozi, passkeys, preuzimanje podataka) traže ponovo lozinku ako je od poslednje prijave prošlo više od 15 minuta. |
| **Zaključavanje** | 3 neuspešna pokušaja zaključavaju nalog na 10 minuta (login, 2FA kodovi, potvrda identiteta, brisanje naloga). |
| **Rate limiting** | Ograničenja po IP adresi za forme naloga (20/min) i za rute koje šalju email (5 na 10 min), odgovor `429` sa `Retry-After`. |
| **Politika lozinki** | 8+ karaktera sa velikim/malim slovom, cifrom i simbolom; ne sme sadržati email; provera u [Have I Been Pwned](https://haveibeenpwned.com/Passwords) bazi procurelih lozinki preko k-anonymity (samo 5 karaktera heša napušta server; ako API nije dostupan, provera se preskače). |
| **Heširanje lozinki** | PBKDF2-HMAC-SHA512 sa 600.000 iteracija; stari heševi se automatski unapređuju pri sledećoj prijavi. |
| **Sesije** | „Odjavi me sa svih drugih uređaja“, security stamp se proverava na 5 minuta, promena lozinke/2FA gasi ostale sesije a trenutnu zadržava. |
| **Bezbednosna obaveštenja** | Email + strukturisani audit log (`Security audit: <Event>`) za promene lozinke/emaila/2FA/passkey-a/načina prijave, zaključavanja i brisanje naloga. |
| **Bez otkrivanja naloga** | Potvrda registracije, ponovno slanje potvrde i reset lozinke odgovaraju isto za nepostojeće naloge; mejlovi idu kroz pozadinski red pa ni vreme odgovora ne otkriva ništa. |
| **Kolačići** | `__Host-` prefiks, `Secure`, `HttpOnly`; antiforgery kolačić `SameSite=Strict`. |
| **Zaglavlja** | Content-Security-Policy sa nonce-om po zahtevu (bez inline skripti), HSTS (1 godina), `X-Frame-Options`, `nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP, bez `Server` zaglavlja, `no-store` na stranicama naloga. |
| **Tokeni i ključevi** | Linkovi za potvrdu/reset ističu posle 3 sata; Data Protection ključevi se čuvaju u bazi pa tokeni i kolačići preživljavaju restart i rade na više instanci. |

Podešavanja (`Security` sekcija u `appsettings.json`):

```json
"Security": {
  "CheckBreachedPasswords": true,
  "SendSecurityNotifications": true,
  "MaxPasskeysPerUser": 10,
  "PasskeyServerDomain": "",      // npr. "example.com" - podrazumevano host iz zahteva
  "KnownProxies": []              // IP adrese reverse proxy-ja kojima se veruje za X-Forwarded-*
}
```

> Passkeys zahtevaju HTTPS (ili `localhost`). Posle ovih izmena napravi novu migraciju - šema sada
> sadrži tabele za passkeys i Data Protection ključeve.

![Passkeys](docs/screenshots/passkeys.png)

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
    "Password": "tvoja-lozinka",
    "From": "no-reply@example.com",
    "FromName": "IdentityToMvc"
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
