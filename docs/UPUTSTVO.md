# Uputstvo: gotov sistem za prijavu i naloge (IdentityToMvc)

Ovaj projekat je **gotov "modul" za prijavu korisnika** koji se može preneti u bilo koju buduću
ASP.NET Core MVC aplikaciju. Svaka aplikacija mora da zna *ko* je korisnik (autentifikacija) i
*šta sme da radi* (autorizacija) - ovde je to već napravljeno, provereno i obezbeđeno.

Najbrži put: nova aplikacija se pravi **jednom komandom** (`dotnet new identitymvc`), uz izbor paketa
(osnovno, standardno, kompletno) i pojedinačnih funkcija - vidi [odeljak 7](#7-nova-aplikacija-jednom-komandom-šablon).

Uputstvo je pisano tako da ga može pratiti i neko ko se ne bavi programiranjem svakodnevno.
Stručni izrazi su objašnjeni u [rečniku](#1-rečnik) na početku.

**Sadržaj**

1. [Rečnik](#1-rečnik)
2. [Velika slika - šta ovaj sistem radi](#2-velika-slika---šta-ovaj-sistem-radi)
3. [Mapa projekta - šta se gde nalazi](#3-mapa-projekta---šta-se-gde-nalazi)
4. [Put jednog klika - kako aplikacija obrađuje zahtev](#4-put-jednog-klika---kako-aplikacija-obrađuje-zahtev)
5. [Funkcionalnosti jedna po jedna](#5-funkcionalnosti-jedna-po-jedna)
6. [Paketi: osnovno, standardno, kompletno](#6-paketi-osnovno-standardno-kompletno)
7. [Nova aplikacija jednom komandom (šablon)](#7-nova-aplikacija-jednom-komandom-šablon)
8. [Autorizacija - kako zaštititi sopstvene stranice](#8-autorizacija---kako-zaštititi-sopstvene-stranice)
9. [Sva podešavanja na jednom mestu](#9-sva-podešavanja-na-jednom-mestu)
10. [Pre puštanja u rad (produkcija)](#10-pre-puštanja-u-rad-produkcija)
11. [Česti problemi i rešenja](#11-česti-problemi-i-rešenja)
12. [Kako da proveriš da sve radi](#12-kako-da-proveriš-da-sve-radi)
13. [Šta je novo u ovoj verziji](#13-šta-je-novo-u-ovoj-verziji)

---

## 1. Rečnik

| Izraz | Šta znači, jednostavno rečeno |
|-------|-------------------------------|
| **Autentifikacija** | Provera *ko si* - kao kada na ulazu u zgradu pokažeš ličnu kartu. U aplikaciji: prijava mejlom i lozinkom, kodom, otiskom prsta... |
| **Autorizacija** | Provera *šta smeš* - kada si već ušao u zgradu, da li imaš ključ od određene kancelarije. U aplikaciji: da li korisnik sme da vidi neku stranicu. |
| **ASP.NET Core** | Microsoft-ov "alat" (framework) za pravljenje web aplikacija u jeziku C#. |
| **Identity** | Deo ASP.NET Core-a koji već zna da čuva korisnike, lozinke, kodove... Ovaj projekat je "lice" (ekrani i logika) oko Identity-ja. |
| **MVC** | Način organizovanja koda na tri dela: **M**odel (podaci), **V**iew (izgled stranice), **C**ontroller (logika - "šta se desi kad klikneš"). |
| **Controller (kontroler)** | Fajl sa logikom. Kad korisnik klikne dugme, kontroler odlučuje šta se dešava. Kao šalterski radnik koji prima zahtev i odgovara. |
| **Akcija** | Jedna funkcija u kontroleru = jedna stranica ili jedno dugme. Npr. `Login` akcija prikazuje stranicu za prijavu. |
| **View (pogled)** | Fajl `.cshtml` - izgled stranice (HTML sa malo C# koda). |
| **ViewModel** | "Formular" - opisuje koja polja stranica ima i koja pravila važe (npr. "mejl je obavezan"). |
| **Area (oblast)** | Folder koji grupiše srodne stranice. Sve oko naloga je u oblasti `User`, pa adrese počinju sa `/User/...`. |
| **Layout** | Zajednički "okvir" svih stranica: gornja traka (meni), podnožje, stilovi. |
| **Partial** | Mali deo stranice koji se koristi na više mesta (npr. poruka "Uspešno sačuvano"). |
| **Program.cs** | "Kontrolna tabla" aplikacije. Tu se uključuju i podešavaju sve funkcije. |
| **appsettings.json** | Fajl sa podešavanjima (adresa baze, mejl server, prekidači funkcija). Menja se bez programiranja. |
| **Middleware** | "Kontrolni punkt" kroz koji prolazi svaki zahtev (npr. punkt koji dodaje sigurnosna zaglavlja). |
| **Filter / atribut** | Oznaka u uglastim zagradama iznad akcije, npr. `[Authorize]`. Kao nalepnica "samo za zaposlene" na vratima. |
| **Baza podataka** | Mesto gde se trajno čuvaju korisnici. Ovde je to SQL Server. |
| **Migracija** | "Recept" koji pravi ili menja tabele u bazi. Gotove migracije su u `Data/Migrations`; nova se pravi komandom `dotnet ef migrations add <Ime>`. |
| **Kolačić (cookie)** | Mala "propusnica" koju browser čuva i šalje uz svaki zahtev. Po njoj aplikacija zna da si prijavljen. |
| **Sesija** | Period dok si prijavljen na jednom uređaju (jedan kolačić = jedna sesija). |
| **Token** | Jednokratni tajni kod, najčešće u linku iz mejla ("klikni da potvrdiš mejl"). |
| **Heš (hash) lozinke** | Lozinka se nikad ne čuva u izvornom obliku - čuva se "otisak" iz kog se lozinka ne može vratiti. Pri prijavi se poredi otisak unete lozinke sa sačuvanim. |
| **2FA (dvofaktorska autentifikacija)** | Pored lozinke traži se i kod iz aplikacije na telefonu (Microsoft/Google Authenticator). Lopov sa lozinkom nema tvoj telefon. |
| **TOTP** | Vrsta šestocifrenog koda koji se menja svakih 30 sekundi u aplikaciji na telefonu. |
| **Recovery kodovi** | Rezervni jednokratni kodovi za slučaj da izgubiš telefon. |
| **Passkey** | Prijava otiskom prsta, licem ili PIN-om uređaja, bez lozinke. Ne može se "upecati" (phishing) jer radi samo na pravom sajtu. |
| **WebAuthn** | Tehnički standard na kome rade passkey-ovi. |
| **Spoljna prijava (external login)** | "Prijavi se preko Google-a / Facebook-a". |
| **Lockout (zaključavanje)** | Posle više pogrešnih lozinki nalog se privremeno zaključava - zaštita od pogađanja. |
| **Rate limiting** | Ograničenje koliko zahteva jedna IP adresa sme da pošalje u minuti - zaštita od "bombardovanja". |
| **IP adresa** | "Kućna adresa" uređaja na internetu. |
| **Security stamp** | Nevidljivi "pečat" naloga. Kad se promeni (npr. promena lozinke), sve stare propusnice (kolačići) prestaju da važe. |
| **Sudo mode** | Pre osetljive izmene aplikacija ponovo traži lozinku, ako je od prijave prošlo više od 15 minuta. |
| **Phishing** | Prevara gde lažni sajt izgleda kao pravi da bi ukrao lozinku. |
| **Enumeracija naloga** | Kada napadač po porukama sajta može da zaključi da li neki mejl ima nalog. Ovaj sistem to sprečava. |
| **HTTPS** | Šifrovana veza (katanac u browseru). Obavezna za passkey-ove i bezbedne kolačiće. |
| **CSP (Content Security Policy)** | Pravilo koje browseru kaže "izvršavaj samo skripte sa mog sajta". Sprečava ubacivanje zlonamernog koda. |
| **Nonce** | Jednokratni nasumični broj kojim se "potpisuje" dozvoljena skripta na stranici. |
| **Zaglavlja (headers)** | Dodatne informacije koje server šalje uz stranicu - mnoge služe za bezbednost. |
| **SMTP** | Protokol za slanje mejlova. Treba ti SMTP server (npr. Gmail, SendGrid, Mailtrap). |
| **Audit log** | Dnevnik bezbednosnih događaja ("ko je, kada i sa koje adrese promenio lozinku"). |
| **Data Protection ključevi** | Tajni ključevi kojima aplikacija šifruje kolačiće i tokene. Čuvaju se u bazi. |
| **Reverse proxy** | Server koji stoji ispred aplikacije i prosleđuje joj zahteve (nginx, IIS, Azure...). |
| **Uloga (role)** | "Funkcija" korisnika, npr. `Admin`. Stranice se mogu otvoriti samo korisnicima sa određenom ulogom. |
| **Admin panel** | Stranice za administratore: pregled korisnika, zaključavanje, uloge, dnevnik događaja. |
| **Lokalizacija** | Prevod aplikacije na više jezika. Ovde: srpski (latinica) i engleski. |
| **Resursni fajl (.resx)** | Fajl sa parovima "engleski tekst → prevod". Jedan fajl po jeziku. |
| **Šifrovanje u mirovanju** | Tajni podaci su šifrovani i dok stoje u bazi - ko ukrade kopiju baze, ne može da ih iskoristi. |
| **Automatski test** | Mali program koji sam "klikće" kroz aplikaciju i proverava da li radi kako treba. |
| **CI (Continuous Integration)** | GitHub posle svake izmene sam pokrene build i testove i javi ako nešto ne radi. |
| **Šablon (template)** | "Kalup" za novu aplikaciju. Komanda `dotnet new identitymvc` od njega napravi gotov projekat sa tvojim imenom i izabranim funkcijama. |
| **NuGet paket** | Spakovan kod koji se instalira jednom komandom. Šablon se može objaviti kao NuGet paket. |
| **CLI / terminal** | Prozor u koji se kucaju komande (`dotnet ...`). U Visual Studio-u: *View → Terminal*. |
| **Namespace** | "Prezime" koda - npr. `IdentityToMvc.Web`. Kad preuzimaš kod u novi projekat, obično ga menjaš. |

---

## 2. Velika slika - šta ovaj sistem radi

Zamisli aplikaciju kao **poslovnu zgradu**:

- **Recepcija** (`AccountController`) - registracija novih "zaposlenih", prijava, odjava, zaboravljena lozinka.
- **Kancelarija za lične podatke** (`ManageController`) - korisnik menja svoj profil, lozinku, mejl, uključuje 2FA, dodaje passkey, briše nalog.
- **Obezbeđenje na ulazu** (`Program.cs` + folder `Security`) - zaključavanje posle pogrešnih pokušaja, ograničenje broja pokušaja, sigurnosna pravila za browser, obaveštenja o sumnjivim promenama.
- **Arhiva** (`Data`) - baza u kojoj se čuvaju korisnici.
- **Pošta** (`Services`) - slanje mejlova (potvrda naloga, reset lozinke, upozorenja).
- **Enterijer** (`Views`, `wwwroot`) - izgled svih stranica, svetla/tamna tema.
- **Upravnik zgrade** (`Areas/Admin`) - administratori vide sve korisnike, mogu da zaključaju nalog, dodele ulogu i pregledaju dnevnik događaja.
- **Prevodilac** (`Localization` + `Resources`) - svaki tekst se prikazuje na srpskom ili engleskom.

**Šta korisnik može da uradi:**

| Za neprijavljene | Za prijavljene (Manage account) |
|------------------|---------------------------------|
| Registracija + potvrda mejla | Profil (broj telefona) |
| Prijava lozinkom | Promena mejla |
| Prijava passkey-om | Promena / postavljanje lozinke |
| Prijava preko Google-a / Facebook-a | Dvofaktorska autentifikacija (2FA) |
| 2FA kod ili recovery kod pri prijavi | Passkey-ovi |
| Zaboravljena lozinka / reset | Spoljne prijave (Google/Facebook) |
| Ponovno slanje potvrde mejla | Uređaji: spisak i odjava pojedinačnog uređaja ili svih |
| Izbor jezika (SR / EN) | Bezbednosna aktivnost (dnevnik događaja na nalogu) |
| | Preuzimanje i brisanje ličnih podataka |
| | **Administratori:** admin panel (`/Admin`) |

---

## 3. Mapa projekta - šta se gde nalazi

Sve je u folderu `IdentityToMvc.Web`.

### Glavni fajlovi

| Fajl | Uloga |
|------|-------|
| `Program.cs` | Kontrolna tabla. Uključuje bazu, Identity, kolačiće, mejl, bezbednost, prekidače. **Najvažniji fajl za razumevanje.** |
| `appsettings.json` | Podešavanja (baza, mejl, prekidači funkcija). |
| `appsettings.Local.json` | Tvoja lokalna podešavanja (lozinke, ključevi) - imaju prednost nad `appsettings.json`. |
| `IdentityToMvc.Web.csproj` | Spisak dodatnih biblioteka (paketa) koje projekat koristi. |

### Folder `Areas/User` - sve oko naloga

| Putanja | Uloga |
|---------|-------|
| `Controllers/AccountController.cs` | **Recepcija**: registracija, potvrda mejla, prijava lozinkom, odjava, zaboravljena i reset lozinke, zaključan nalog. |
| `Controllers/AccountController.<Funkcija>.cs` | Delovi recepcije po funkcijama: `.TwoFactor` (2FA kod i recovery kod pri prijavi), `.Passkeys` (prijava passkey-om), `.ExternalLogins` (Google/Facebook), `.UnlockLink` (link za otključavanje). |
| `Controllers/ManageController.cs` | **Kancelarija naloga**: zajednički deo + promena i postavljanje lozinke. |
| `Controllers/ManageController.<Funkcija>.cs` | Ostale stranice naloga, svaka funkcija u svom fajlu: `.Profile`, `.Email`, `.TwoFactor`, `.Passkeys`, `.ExternalLogins`, `.PersonalData`, `.Devices`, `.Activity`, `.ConfirmIdentity` (sudo). |
| `ViewModels/Account/*.cs` | "Formulari" za stranice recepcije (koja polja i pravila). |
| `ViewModels/Manage/*.cs` | "Formulari" za stranice naloga. |
| `Views/Account/*.cshtml` | Izgled stranica recepcije (Login, Register, ForgotPassword...). |
| `Views/Manage/*.cshtml` | Izgled stranica naloga (Index = profil, Email, ChangePassword, Passkeys...). |
| `Views/Manage/_ManageLayout.cshtml` + `_ManageNav.cshtml` | Okvir i bočni meni stranica naloga. |
| `Views/Shared/_ExternalLoginButtons.cshtml` | Dugmad "Prijavi se preko Google-a/Facebook-a". |

### Folder `Security` - napredna zaštita

| Fajl | Uloga |
|------|-------|
| `SecurityOptions.cs` | **Prekidači** - koja napredna funkcija je uključena (čita se iz `appsettings.json`). |
| `FeatureGateAttribute.cs` | Ako je funkcija isključena, njene stranice vraćaju "404 - ne postoji". |
| `SecurityHeadersMiddleware.cs` | Dodaje sigurnosna zaglavlja i CSP na svaki odgovor. |
| `RateLimitPolicies.cs` | Pravila ograničenja broja zahteva po IP adresi. |
| `BreachedPasswordValidator.cs` | Proverava da lozinka nije procurela (Have I Been Pwned) i da ne sadrži mejl. |
| `RecentAuthentication.cs` | **Sudo mode** - pamti kada si se poslednji put dokazao i traži lozinku ponovo pre osetljivih izmena. |
| `RefreshSessionOnSecurityStampChangeFilter.cs` | Posle promene "pečata" naloga zadržava *tvoju* sesiju, a gasi ostale. |
| `SecurityNotifier.cs` | Upisuje događaj u audit log (baza + log) i šalje mejl upozorenja. Tu je i spisak svih događaja i njihovi tekstovi. |
| `UserInfoPasswordValidator.cs` | Lozinka ne sme da sadrži mejl korisnika. |
| `PasswordTimingEqualizer.cs` | Prijava traje isto dugo bez obzira da li nalog postoji (napadač ne može da "meri" vreme). |
| `ProtectedUserStore.cs` | Šifruje 2FA ključ i čuva samo heševe recovery kodova. |
| `SessionService.cs` | Vodi evidenciju uređaja (sesija): pravi, proverava i gasi sesije, šalje mejl za novi uređaj. |
| `DeviceDescriber.cs` | Od podataka browsera pravi opis "Chrome · Windows". |
| `AdminBootstrapper.cs` | Pravi ulogu `Admin` i dodeljuje je mejlovima iz `Admin:Emails`. |
| `RequireAdminSecurityAttribute.cs` | Administrator bez 2FA/passkey-a ne može u admin panel. |

### Folder `Areas/Admin` - admin panel

| Putanja | Uloga |
|---------|-------|
| `Controllers/AdminControllerBase.cs` | Zajednička "brava" svih admin stranica: samo uloga `Admin`, obavezna 2FA, ograničenje zahteva. |
| `Controllers/DashboardController.cs` | Pregled: broj korisnika, sa 2FA, zaključani, prijave u poslednja 24 sata, poslednji događaji. |
| `Controllers/UsersController.cs` | Spisak i pretraga korisnika, detalji i radnje nad nalogom. |
| `Controllers/RolesController.cs` | Pravljenje i brisanje uloga. |
| `Controllers/AuditController.cs` | Ceo dnevnik događaja sa pretragom. |
| `ViewModels/AdminViewModels.cs` | "Formulari" admin stranica. |
| `Views/...` | Izgled admin stranica; `Shared/_AdminLayout.cshtml` je okvir sa bočnim menijem. |

### Folderi `Localization` i `Resources` - jezici

| Putanja | Uloga |
|---------|-------|
| `Localization/LocalizationSetup.cs` | Koji jezici postoje, koji je podrazumevani, kako se bira jezik (kolačić → browser → podrazumevani). |
| `Localization/SharedResource.cs` | Prazna "oznaka" za zajednički fajl prevoda. |
| `Localization/LocalizedIdentityErrorDescriber.cs` | Prevodi poruke koje pravi sam Identity ("Lozinka mora imati..."). |
| `Localization/StatusMessageExtensions.cs` | Pomoćne funkcije `this.StatusSuccess(...)` / `this.StatusError(...)` za zelene/crvene poruke. |
| `Resources/SharedResource.sr-Latn.resx` | **Svi srpski prevodi** (engleski tekst → srpski tekst). |

### Ostali folderi

| Putanja | Uloga |
|---------|-------|
| `Services/EmailService.cs` | Šalje mejl preko SMTP-a. |
| `Services/EmailQueue.cs` | Red za mejlove - šalju se u pozadini. |
| `Services/EmailTemplates.cs` | Izgled i tekst mejlova (HTML šabloni, prevedeni). |
| `Services/DataRetentionService.cs` | Na 12 sati briše stare zapise iz dnevnika i stare sesije. |
| `Settings/SmtpSettings.cs` | Opis SMTP podešavanja (server, port, korisnik...). |
| `Helpers/AuthenticatorHelper.cs` | Pravi ključ i QR kod za aplikaciju na telefonu (2FA). |
| `Helpers/TokenEncoder.cs` | Pakuje tokene u linkove i bezbedno ih raspakuje. |
| `Data/ApplicationDbContext.cs` | Veza sa bazom (tabele korisnika, ključevi, `SecurityEvents`, `UserSessions`). |
| `Data/SecurityEventRecord.cs` | Jedan red dnevnika: ko, šta, kada, sa koje IP adrese i uređaja. |
| `Data/UserSession.cs` | Jedna prijava na jednom uređaju. |
| `Data/Migrations/SqlServer`, `Postgres`, `Sqlite` | Gotove migracije ("recepti" za tabele) za svaku bazu. Nova aplikacija dobija samo one za izabranu bazu. |
| `Controllers/HomeController.cs` | Početna, Privacy, stranice grešaka (404, 429...), promena jezika (`SetLanguage`). |
| `Views/Shared/_StatusMessage.cshtml` | Zelena/crvena poruka ("Sačuvano" / "Greška") - koriste je i nalog i admin panel. |
| `Views/Shared/_Layout.cshtml` | Zajednički okvir svih stranica. |
| `Views/Shared/_LoginPartial.cshtml` | Desni deo gornje trake: "Log in / Sign up" ili meni prijavljenog korisnika. |
| `wwwroot/css/site.css` | Boje, tema (svetla/tamna), izgled kartica i dugmadi. |
| `wwwroot/js/site.js` | Tema, prikaži/sakrij lozinku, jačina lozinke, kopiranje, potvrde. |
| `wwwroot/js/passkeys.js` | Komunikacija browsera sa otiskom prsta / Face ID-om. |
| `wwwroot/js/site.qrcode.js` | Crta QR kod za 2FA. |
| `wwwroot/lib/` | Tuđe biblioteke: Bootstrap (izgled), Bootstrap Icons (ikonice), jQuery i validacija, qrcodejs. |

> Kontroleri su podeljeni na više fajlova (C# `partial class`) upravo zato da **svaka funkcija bude u svom fajlu** -
> šablon izbacuje ceo fajl kada funkcija nije izabrana, a ti odmah vidiš šta pripada čemu.

Van foldera `IdentityToMvc.Web`:

| Putanja | Uloga |
|---------|-------|
| `.template.config/` | Opis šablona `dotnet new identitymvc`: paketi, prekidači, koji fajlovi pripadaju kojoj funkciji. |
| `templates/feature/` | Šablon `dotnet new identitymvc-add` (dodavanje funkcije u postojeću aplikaciju) i uputstva `ADD-<funkcija>.md`. Pravi se automatski skriptom `tools/build_feature_template.py`. |
| `templates/IdentityToMvc.Templates.csproj` | Pakuje oba šablona u NuGet paket (za objavljivanje). |
| `IdentityToMvc.Tests/` | Automatski testovi (vidi 5.22). |
| `tools/extract_keys.py` | Pronalazi tekstove koji još nemaju srpski prevod. |
| `.github/workflows/ci.yml` | CI: GitHub posle svake izmene sam proveri prevode, build i testove. |
| `global.json` | Kaže `dotnet test` komandi koji "pokretač testova" da koristi. |

---

## 4. Put jednog klika - kako aplikacija obrađuje zahtev

Kada korisnik klikne "Log in", zahtev prolazi kroz niz "punktova" definisanih u `Program.cs`
(donji deo fajla, posle `var app = builder.Build();`), **tačno ovim redom**:

1. **`UseForwardedHeaders`** - ako ispred aplikacije stoji reverse proxy, saznaje pravu IP adresu korisnika.
2. **`UseExceptionHandler` / `UseHsts`** (samo u produkciji) - lepa stranica greške; browseru se kaže "uvek koristi HTTPS".
3. **`SecurityHeadersMiddleware`** - lepi sigurnosna zaglavlja i pravi jednokratni *nonce* za skripte.
4. **`UseStatusCodePagesWithReExecute`** - greške 404/429 prikazuje kao lepe stranice.
5. **`UseHttpsRedirection`** - prebacuje `http://` na `https://`.
6. **`UseRequestLocalization`** - bira jezik (srpski ili engleski) za ovaj zahtev.
7. **`UseRouting`** - pronalazi koji kontroler i koja akcija odgovaraju adresi.
8. **`UseRateLimiter`** - proverava da ista IP adresa nije poslala previše zahteva.
9. **`UseAuthentication`** - čita kolačić i utvrđuje *ko* je korisnik; proverava i da ta sesija (uređaj) nije ugašena.
10. **`UseAuthorization`** - proverava *da li sme* (npr. `[Authorize]` na `ManageController`, uloga `Admin` za admin panel).
11. **Kontroler i akcija** - izvršava se logika, pa se prikazuje stranica (View).

> **Važno:** redosled ovih linija je bitan. Ako prenosiš kod, zadrži isti redosled.

---

## 5. Funkcionalnosti jedna po jedna

Za svaku funkcionalnost piše: **šta korisnik vidi**, **kako radi iza scene**, **koji fajlovi** i
**kako se isključuje**.

### 5.1 Registracija i potvrda mejla

- **Korisnik vidi:** stranicu `Sign up` (mejl + lozinka dva puta). Posle toga poruku "Proveri mejl".
  U mejlu je link; klikom na njega nalog postaje aktivan.
- **Iza scene:**
  1. `AccountController.Register` proverava formular i pravila lozinke, pa pravi korisnika u bazi.
  2. Pravi se token za potvrdu, pakuje se u link (`TokenEncoder`) i mejl se stavlja **u red** (`EmailQueue`).
  3. Dok mejl nije potvrđen, prijava nije moguća (`RequireConfirmedAccount = true` u `Program.cs`).
  4. `ConfirmEmail` proverava token i označava mejl kao potvrđen.
- **Za testiranje bez mejl servera:** u *Development* okruženju stranica "Proveri mejl" sama prikaže link za potvrdu.
- **Fajlovi:** `AccountController` (akcije `Register`, `RegisterConfirmation`, `ConfirmEmail`, `ResendEmailConfirmation`),
  `Views/Account/Register.cshtml`, `RegisterConfirmation.cshtml`, `ConfirmEmail.cshtml`, `ResendEmailConfirmation.cshtml`,
  `ViewModels/Account/RegisterViewModel.cs`, `Services/EmailTemplates.cs` (`ConfirmAccount`).
- **Bezbednost:**
  - stranice ne otkrivaju da li mejl već postoji (isti odgovor za sve);
  - ako neko pokuša da registruje **već potvrđen** mejl, dobija isti odgovor kao i svi, a pravi vlasnik dobija mejl
    "Već imate nalog" sa linkovima za prijavu i reset lozinke;
  - **nepotvrđen** nalog ne "zauzima" adresu: ako napadač registruje tuđi mejl i ne potvrdi ga, nova registracija
    pravog vlasnika briše napadačev nalog. Tako napadač ne može unapred da postavi lozinku za tuđi nalog;
  - "Resend email confirmation" šalje link za **postavljanje nove lozinke** i aktivaciju - ko god je prvi napravio
    nalog, lozinku na kraju bira vlasnik mejla.
- **Isključivanje potvrde mejla:** u `Program.cs` postaviti `RequireConfirmedAccount` i `RequireConfirmedEmail` na `false` -
  korisnik se tada odmah prijavljuje posle registracije. (Ne preporučuje se za javne sajtove.)

### 5.2 Prijava i odjava

- **Korisnik vidi:** `Log in` stranicu - mejl, lozinka, "Remember me", link za zaboravljenu lozinku.
- **Iza scene:** `AccountController.Login` poziva Identity (`PasswordSignInAsync`). Ako je sve u redu, browser dobija
  kolačić `__Host-IdentityToMvc.Auth` koji važi 1 sat i produžava se dok je korisnik aktivan.
  Ako korisnik ima 2FA, šalje se na stranicu za kod. Odjava (`Logout`) briše kolačić.
- **Fajlovi:** `AccountController` (`Login`, `Logout`), `Views/Account/Login.cshtml`, `Views/Shared/_LoginPartial.cshtml`.
- **Isto vreme odgovora:** za nepostojeći, nepotvrđen ili zaključan nalog aplikacija ipak "izračuna" jedan heš lozinke
  (`PasswordTimingEqualizer`), pa napadač po brzini odgovora ne može da zaključi koji mejlovi imaju nalog.
- **Svaka prijava je sesija:** pravi se zapis u tabeli `UserSessions` (uređaj, IP, vreme), a neuspeli pokušaji se upisuju
  u dnevnik (`LoginFailed`). Odjava gasi tu sesiju.
- **Posle prijave** korisnik se vraća na stranicu na koju je hteo da ode (`returnUrl`), ali **samo ako je adresa na istom sajtu** -
  zaštita od preusmeravanja na lažne sajtove.

### 5.3 Zaključavanje naloga (lockout)

- **Korisnik vidi:** posle **3 pogrešne lozinke** stranicu "Account temporarily locked". Zaključavanje traje **10 minuta**.
  Vlasnik naloga dobija mejl upozorenja.
- **Gde se broje promašaji:** prijava lozinkom, 2FA kod, "Confirm it's you" (sudo), brisanje naloga.
- **Otključavanje:** automatski posle 10 minuta, ili odmah uspešnim resetom lozinke.
- **Zaštita od zloupotrebe:** neko ko zna tvoj mejl bi mogao stalno da ukucava pogrešne lozinke i drži ti nalog zaključanim.
  Zato vlasnik u mejlu dobija **link za otključavanje**, a prijava **passkey-om** radi i dok je nalog zaključan zbog
  pogrešnih lozinki.
- **Zaključavanje od strane administratora** (admin panel) je trajno - ne skida ga ni link, ni passkey, ni reset lozinke.
- **Fajlovi:** `AccountController.cs` (`Login`, `Lockout`, `NotifyIfJustLockedOutAsync`), `AccountController.UnlockLink.cs`.
- **Podešavanje:** `Program.cs` → `options.Lockout.MaxFailedAccessAttempts = 3;` i `DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);`

### 5.4 Zaboravljena lozinka i reset

- **Korisnik vidi:** "Forgot password?" → unese mejl → dobije link → izabere novu lozinku.
- **Iza scene:** `ForgotPassword` šalje mejl samo ako nalog postoji i mejl je potvrđen, ali korisniku **uvek** prikazuje istu
  poruku (napadač ne može da sazna koji mejlovi postoje). Link važi **3 sata**. Posle reseta se gase sve ostale sesije
  (promeni se "pečat") i skida se zaključavanje.
- **Fajlovi:** `AccountController` (`ForgotPassword`, `ResetPassword`...), `Views/Account/ForgotPassword.cshtml`,
  `ResetPassword.cshtml`, `ForgotpasswordConfirmation.cshtml`, `ResetPasswordConfirmation.cshtml`.

### 5.5 Profil, promena lozinke i mejla

- **Profil** (`Manage/Index`): broj telefona. ("Sign out everywhere" je na stranici *Devices*, vidi 5.11.)
- **Lozinka** (`Manage/ChangePassword`): traži staru i novu lozinku. Ako korisnik nema lozinku (ušao je preko Google-a),
  prikazuje se `SetPassword`. Posle promene: ostale sesije se gase, stiže mejl upozorenja.
- **Mejl** (`Manage/Email`): novi mejl dobija link za potvrdu; **stari mejl dobija upozorenje**. Mejl se menja tek
  kada se klikne link, i to samo ako je prijavljen isti korisnik koji je tražio promenu.
- **Fajlovi:** `ManageController.cs` (lozinka), `ManageController.Profile.cs` (profil), `ManageController.Email.cs`
  (promena mejla) i odgovarajući view-ovi u `Views/Manage`.

### 5.6 Dvofaktorska autentifikacija (2FA) i recovery kodovi

- **Korisnik vidi:** Manage → *Two-factor authentication* → "Add authenticator app" → skenira QR kod telefonom →
  upiše šestocifreni kod → dobije **10 recovery kodova** (može da ih kopira ili preuzme kao `.txt`).
  Od tada se pri prijavi traži kod iz aplikacije. Opcija "Remember this device" preskače kod na tom uređaju.
- **Iza scene:** `AuthenticatorHelper` pravi tajni ključ i adresu za QR kod; `site.qrcode.js` ga crta; Identity proverava
  kodove. Recovery kodovi važe po jednom.
- **Fajlovi:** `ManageController.TwoFactor.cs`, `AccountController.TwoFactor.cs`, view-ovi sa istim imenima, `Helpers/AuthenticatorHelper.cs`, `wwwroot/js/site.qrcode.js`,
  `wwwroot/lib/qrcodejs`.
- **Isključivanje:** `"EnableTwoFactor": false` u `appsettings.json`. Nestaju meni i stranice (vraćaju 404).
  *Napomena:* korisnici koji su 2FA već uključili i dalje moraju da unose kod pri prijavi.

### 5.7 Passkeys (prijava otiskom prsta / licem)

- **Korisnik vidi:** Manage → *Passkeys* → upiše naziv (npr. "Moj laptop") → "Add a passkey" → telefon/računar traži
  otisak prsta, lice ili PIN. Na `Log in` stranici: dugme **"Log in with a passkey"**, a polje za mejl samo nudi
  sačuvane passkey-ove.
- **Iza scene:** server napravi "izazov" (`PasskeyCreationOptions` / `PasskeyRequestOptions`), browser ga potpiše
  uređajem (`passkeys.js`), a server proveri potpis (`AddPasskey` / `LoginWithPasskey`). Tajni deo **nikad ne napušta uređaj**.
  Pošto uređaj proverava otisak/PIN, passkey sam po sebi vredi kao lozinka + 2FA.
- **Ograničenja:** najviše 10 passkey-ova po korisniku (`MaxPasskeysPerUser`). Ne može se obrisati poslednji način prijave.
- **Zahtev:** radi samo preko **HTTPS-a** (ili na `localhost`).
- **Fajlovi:** `ManageController.Passkeys.cs`, `AccountController.Passkeys.cs`, `Views/Manage/Passkeys.cshtml`,
  `ViewModels/Manage/PasskeysViewModel.cs`, `wwwroot/js/passkeys.js`, deo `Login.cshtml`.
  U `Program.cs`: `options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;` i blok `Configure<IdentityPasskeyOptions>`.
- **Isključivanje:** `"EnablePasskeys": false`.

### 5.8 Spoljne prijave (Google, Facebook)

- **Korisnik vidi:** dugmad "Log in with Google/Facebook" na Login i Sign up stranicama, i stranicu *External logins* u nalogu.
- **Uključivanje:** upiši ključeve u `appsettings.Local.json` (ili user-secrets):
  `GoogleClientId`, `GoogleClientSecret`, `FacebookAppId`, `FacebookAppSecret`.
  Ključeve dobijaš na Google Cloud Console / Meta for Developers. **Ako ključ nije upisan, dugme se ne prikazuje.**
- **Bezbednost:** i posle Google prijave traži se 2FA ako ga korisnik ima; ne može se ukloniti poslednji način prijave.
  Nalog se pravi samo sa mejlom koji je **Google/Facebook potvrdio**, i spoljna prijava se **nikad sama ne povezuje** sa
  postojećim nalogom - vlasnik je povezuje sam, prijavljen, na stranici *External logins*.
- **Fajlovi:** `AccountController.ExternalLogins.cs`, `ManageController.ExternalLogins.cs`,
  `Views/Account/ExternalLogin.cshtml`, `Views/Manage/ExternalLogins.cshtml`, `Views/Shared/_ExternalLoginButtons.cshtml`.
- **Drugi provajderi** (Microsoft, GitHub...): dodaju se u `Program.cs` na isti način kao Google (poseban paket).
  Ako dodaješ novi provajder, dodaj njegovu adresu i u `form-action` u `SecurityHeadersMiddleware.cs`.

### 5.9 Lični podaci i brisanje naloga (GDPR)

- **Korisnik vidi:** Manage → *Personal data* → "Download" (JSON fajl sa svim podacima) ili "Delete account"
  (traži lozinku i potvrdu).
- **Fajlovi:** `ManageController.PersonalData.cs`, view-ovi `PersonalData` i `DeletePersonalData`.
- **Napomena:** ako tvoja aplikacija čuva i druge podatke o korisniku (porudžbine, komentare...), dopuni `DeletePersonalData`
  da briše i njih, a `DownloadPersonalData` da ih izvozi.

### 5.10 Sudo mode (ponovna potvrda identiteta)

- **Korisnik vidi:** kada je od prijave prošlo više od **15 minuta**, pre osetljive izmene pojavljuje se
  "Confirm it's you" i traži se lozinka. Posle toga 15 minuta se ne pita ponovo.
- **Zašto:** ako neko sedne za tvoj otključan računar ili ukrade kolačić, ne može da isključi 2FA, promeni mejl i preuzme nalog.
- **Zaštićene radnje:** uključivanje/isključivanje/reset 2FA, novi recovery kodovi, promena mejla, dodavanje/uklanjanje
  spoljne prijave i passkey-a, preuzimanje ličnih podataka. (Promena lozinke i brisanje naloga ionako traže lozinku.)
- **Kako radi:** pri svakoj pravoj prijavi upisuje se šifrovani kolačić `__Host-IdentityToMvc.Reauth` koji važi 15 minuta.
  Akcije označene sa `[RequireRecentAuthentication]` proveravaju taj kolačić.
- **Korisnici bez lozinke** (samo Google/Facebook/passkey) se ne pitaju.
- **Fajlovi:** `Security/RecentAuthentication.cs`, `ManageController.ConfirmIdentity.cs`, `Views/Manage/ConfirmIdentity.cshtml`,
  `ViewModels/Manage/ConfirmIdentityViewModel.cs`.
- **Isključivanje:** `"RequireRecentAuthentication": false`. **Dodavanje na tvoju stranicu:** stavi `[RequireRecentAuthentication]` iznad akcije.

### 5.11 Uređaji i odjava sa svih uređaja

- **Korisnik vidi:** Manage → *Devices* - spisak uređaja na kojima je prijavljen ("Chrome · Windows", IP adresa,
  kada je poslednji put korišćen), sa oznakom "This device" za trenutni. Pored svakog je dugme za odjavu, a na dnu
  "Sign out everywhere" (svi osim trenutnog).
- **Kako radi:** pri prijavi se u kolačić upisuje broj sesije (`sid`), a u bazu red u tabeli `UserSessions`.
  Pri svakom zahtevu se proverava da ta sesija nije ugašena - zato odjava uređaja deluje **odmah**.
  "Sign out everywhere" dodatno menja "pečat" naloga (security stamp), pa se zaboravljaju i "zapamćeni uređaji" za 2FA.
- **Mejl za novi uređaj:** kada se korisnik prijavi sa uređaja koji do sada nije koristio, dobija mejl
  (sa vremenom, IP adresom i uređajem). Prva prijava ikada ne šalje mejl.
- **Fajlovi:** `Security/SessionService.cs`, `Security/DeviceDescriber.cs`, `Data/UserSession.cs`,
  `ManageController.Devices.cs`, `Views/Manage/Devices.cshtml`, deo `Program.cs`
  (`OnSigningIn` i `OnValidatePrincipal` kod kolačića).
- **Čišćenje:** sesije starije od `Security:SessionRetentionDays` (30 dana) brišu se automatski.
- **Isto se automatski dešava** posle promene lozinke, reseta lozinke, uključivanja/isključivanja 2FA i sličnih izmena -
  a `RefreshSessionOnSecurityStampChangeFilter` pazi da tebe pri tome ne izbaci.

### 5.12 Bezbednosna obaveštenja i audit log

- **Korisnik dobija mejl** kada se: promeni/resetuje/postavi lozinka, traži ili izvrši promena mejla (ide na *stari* mejl),
  uključi/isključi 2FA, resetuje authenticator ključ, generišu novi recovery kodovi, doda/ukloni spoljna prijava ili passkey,
  izvrši odjava sa svih uređaja, zaključa nalog, obriše nalog. U mejlu su vreme, IP adresa i uređaj.
- **Audit log:** svaki događaj (i neuspela prijava, i radnja administratora) se upisuje:
  - u **bazu**, tabela `SecurityEvents` - odatle ga čitaju stranica *Security activity* i admin panel;
  - u **log** u obliku `Security audit: PasswordChanged for user <id> from <IP> (<uređaj>)` - logovi se mogu slati u alat
    za praćenje (Seq, Application Insights, ELK...).
- **Korisnik vidi:** Manage → *Security activity* - vremensku liniju svojih događaja (prijave, neuspeli pokušaji,
  promene), sa ikonicama i bojama (crveno = sumnjivo).
- **Čišćenje:** zapisi stariji od `Security:AuditRetentionDays` (365 dana) brišu se automatski (`DataRetentionService`).
- **Fajlovi:** `Security/SecurityNotifier.cs` (spisak događaja i tekstovi), `Data/SecurityEventRecord.cs`,
  `ManageController.Activity.cs`, `Views/Manage/Activity.cshtml`, `Services/EmailTemplates.cs` (`SecurityNotification`).
- **Isključivanje mejlova:** `"SendSecurityNotifications": false` (audit log ostaje).

### 5.13 Ograničenje broja zahteva (rate limiting)

- **Pravila po IP adresi:**
  - forme naloga (prijava, 2FA, promene): najviše **20 u minuti**;
  - forme koje šalju mejl (registracija, zaboravljena lozinka, ponovno slanje potvrde): najviše **5 na 10 minuta**.
- Kada se pređe granica, prikazuje se stranica **"429 - Too many requests"**.
- **Razlika od zaključavanja:** zaključavanje štiti *jedan nalog*; rate limiting štiti od *jednog napadača* koji pokušava mnogo naloga.
- **Fajlovi:** `Security/RateLimitPolicies.cs` (brojevi se menjaju tu), oznake `[EnableRateLimiting(...)]` na kontrolerima.
- **Isključivanje:** `"EnableRateLimiting": false`.
- **Važno iza reverse proxy-ja:** upiši IP adresu proxy-ja u `"KnownProxies"`, inače svi korisnici izgledaju kao jedna IP adresa.

### 5.14 Pravila lozinke, procurele lozinke i heširanje

- **Pravila:** najmanje **8 karaktera**, veliko i malo slovo, cifra, simbol, bar 4 različita znaka, ne sme da sadrži mejl.
  Menjaju se u `Program.cs` (`options.Password...`) - **i** u ViewModel-ima (`MinimumLength = 8`) da poruke budu iste.
- **Procurele lozinke:** nova lozinka se proverava u bazi [Have I Been Pwned](https://haveibeenpwned.com/Passwords)
  (milijarde lozinki iz poznatih curenja). Serveru se šalje samo prvih 5 znakova "otiska" - sama lozinka nikad ne napušta
  aplikaciju. Ako servis nije dostupan, provera se preskače (korisnik nije blokiran).
  Fajl: `Security/BreachedPasswordValidator.cs`. Isključivanje: `"CheckBreachedPasswords": false`.
- **Heširanje:** PBKDF2 sa 600.000 ponavljanja (preporuka OWASP-a) - pogađanje ukradene baze je izuzetno sporo.
  Stare lozinke se automatski prebacuju na jači heš pri sledećoj prijavi.

### 5.15 Sigurnosna zaglavlja i kolačići

- **Zaglavlja** (`Security/SecurityHeadersMiddleware.cs`), na svakom odgovoru:
  - **CSP** - browser izvršava samo skripte sa sajta ili one sa tačnim nonce-om. Zato **nema skripti direktno u HTML-u**;
    ako moraš, dodaj `nonce="@Context.GetCspNonce()"` na `<script>` tag.
  - Zabrana prikaza sajta u tuđem okviru (clickjacking), `nosniff`, `Referrer-Policy`, `Permissions-Policy`, COOP/CORP.
  - Stranice naloga se **ne keširaju** (dugme "Nazad" posle odjave ne prikazuje podatke).
  - Server ne otkriva koji softver koristi.
  - U produkciji: HSTS 1 godina ("uvek HTTPS").
- **Kolačići:** svi imaju `__Host-` prefiks (browser ih prihvata samo preko HTTPS-a i samo za ovaj sajt), `HttpOnly`
  (JavaScript ne može da ih pročita), zaštitni kolačić protiv lažnih formi je `SameSite=Strict`.
- **Ako dodaješ spoljne skripte ili slike** (npr. Google Analytics, CDN), moraš ih dozvoliti u CSP-u u
  `SecurityHeadersMiddleware.cs` - inače ih browser blokira.

### 5.16 Mejlovi

- **Podešavanje:** sekcija `"SMTP"` u `appsettings.json` / `appsettings.Local.json`:
  `Host`, `Port` (najčešće 587), `EnableSsl`, `Username`, `Password`, `From` (adresa pošiljaoca), `FromName`.
- **Red za mejlove** (`EmailQueue`): mejlovi sa javnih stranica se šalju u pozadini - stranica odgovara odmah, a napadač po
  brzini odgovora ne može da zaključi da li nalog postoji.
- **Ako slanje ne uspe:** greška se upisuje u log, aplikacija nastavlja da radi.
- **Izgled mejlova:** `Services/EmailTemplates.cs`.
- **Drugi način slanja** (SendGrid API, Amazon SES...): napravi novu klasu koja implementira `IEmailService` i zameni je u
  `Program.cs` (`AddSingleton<IEmailService, TvojaKlasa>()`).

### 5.17 Ključevi i tokeni

- **Data Protection ključevi** se čuvaju u bazi (tabela `DataProtectionKeys`) - posle restarta ili kada aplikacija radi na
  više servera, korisnici ostaju prijavljeni i linkovi iz mejlova rade.
- **Šifrovanje ključeva sertifikatom (preporuka za produkciju):** upiši putanju do `.pfx` sertifikata u
  `Security:DataProtectionCertificatePath` (i lozinku u `DataProtectionCertificatePassword`). Tada kopija baze sama
  nije dovoljna da se dešifruju kolačići, tokeni i 2FA ključevi. Bez sertifikata aplikacija u produkciji upisuje upozorenje u log.
- **2FA tajne u bazi:** ključ za aplikaciju na telefonu se čuva **šifrovan** (`enc:...`), a recovery kodovi samo kao
  **heševi** (`h1:...`), kao lozinke. Stari, nešifrovani zapisi i dalje rade i zamenjuju se pri sledećoj izmeni.
  Fajl: `Security/ProtectedUserStore.cs` (uključen u `Program.cs` sa `.AddUserStore<ProtectedUserStore>()`).
- **Trajanje linkova iz mejla:** 3 sata (`TokenLifespan` u `Program.cs`).
- **Provera "pečata" naloga:** na 5 minuta (`ValidationInterval` u `Program.cs`).

### 5.18 Izgled

- **Tema:** boje su na vrhu `wwwroot/css/site.css` (`--app-primary`, `--app-accent`...). Promeni te vrednosti i cela
  aplikacija dobija novi izgled - posebno za svetlu (`[data-bs-theme="light"]`) i tamnu (`[data-bs-theme="dark"]`) temu.
- **Ime i logo:** `Views/Shared/_Layout.cshtml` (tekst "IdentityToMvc" i ikonica u gornjoj traci).
- **Tekstovi na stranicama** su u kodu napisani na engleskom, a prikazuju se na jeziku korisnika (vidi 5.19).
- **Biblioteke:** Bootstrap 5.3 (raspored, dugmad), Bootstrap Icons (ikonice - spisak na icons.getbootstrap.com).

### 5.19 Lokalizacija (srpski i engleski)

- **Korisnik vidi:** prekidač **SR / EN** u gornjoj traci. Izbor se pamti godinu dana (kolačić `__Host-IdentityToMvc.Culture`).
- **Kako se bira jezik:** 1) izbor sa prekidača; 2) jezik browsera (srpski, hrvatski, bosanski i crnogorski → srpski);
  3) podrazumevani jezik iz `Localization:DefaultCulture` (`sr-Latn-RS` ili `en`).
- **Šta je prevedeno:** sve stranice, poruke, mejlovi, poruke validacije formi ("Polje je obavezno"), poruke Identity-ja
  ("Lozinka mora imati bar jednu cifru"), tekstovi u JavaScript-u (jačina lozinke, passkey greške).
- **Kako radi:** u kodu je tekst na engleskom, npr. u view-u `@L["Log in"]`, u kontroleru `_t["Your profile has been updated"]`.
  Taj engleski tekst je "ključ" - aplikacija ga traži u `Resources/SharedResource.sr-Latn.resx` i prikazuje prevod
  ("Prijavi se"). Ako prevoda nema, prikazuje se engleski tekst (ništa se ne kvari).
- **Dodavanje ili izmena teksta:**
  1. U kodu napiši tekst na engleskom kroz `L[...]` (view) ili `_t[...]` (kontroler).
  2. Pokreni `python3 tools/extract_keys.py` - ispisaće tekstove bez prevoda.
  3. Otvori `SharedResource.sr-Latn.resx` u Visual Studio-u (tabela Name / Value) i dodaj red: *Name* = engleski tekst,
     *Value* = srpski prevod.
- **Novi jezik** (npr. nemački): napravi `SharedResource.de.resx` sa istim ključevima i dodaj jezik u
  `LocalizationSetup.cs` (spisak `SupportedCultures`) i dugme u `_Layout.cshtml`.
- **Samo jedan jezik:** najlakše pri pravljenju aplikacije (`--lang sr` ili `--lang en`). U postojećoj aplikaciji:
  postavi `DefaultCulture` na željeni jezik i ukloni formu `language-form` iz `_Layout.cshtml`.
- **Fajlovi:** folder `Localization`, folder `Resources`, `HomeController.SetLanguage`, deo `_Layout.cshtml`,
  u `Program.cs` `AddLocalization`, `AddViewLocalization`, `AddDataAnnotationsLocalization` i `UseRequestLocalization`.

### 5.20 Admin panel

- **Ko ga vidi:** samo korisnici sa ulogom **`Admin`** - u korisničkom meniju im se pojavljuje *Admin panel* (`/Admin`).
- **Kako se postaje administrator:**
  1. Upiši mejl u `appsettings.json` (ili `appsettings.Local.json`): `"Admin": { "Emails": [ "ti@firma.rs" ] }`.
  2. Registruj se tim mejlom i potvrdi ga (ako nalog već postoji i potvrđen je - samo restartuj aplikaciju).
  3. Uključi 2FA ili dodaj passkey - bez toga admin panel šalje na stranicu za podešavanje 2FA
     (može se isključiti sa `Security:RequireTwoFactorForAdmins: false`, ne preporučuje se).
  4. Dalje administratori dodeljuju ulogu drugima u samom panelu.
- **Šta sve može:**
  - **Pregled** - broj korisnika, potvrđeni, sa 2FA, sa passkey-om, zaključani, aktivne sesije, prijave / neuspeli
    pokušaji / zaključavanja u poslednja 24 sata, poslednji događaji;
  - **Korisnici** - pretraga po mejlu, detalji (sesije, događaji, uloge, načini prijave), i radnje:
    zaključaj / otključaj, odjavi sa svih uređaja, resetuj 2FA, potvrdi mejl, promeni uloge, obriši nalog;
  - **Uloge** - napravi novu ulogu (npr. `Urednik`) ili obriši postojeću (uloga `Admin` se ne može obrisati);
  - **Audit log** - svi događaji svih korisnika, sa pretragom po mejlu i vrsti događaja.
- **Zaštite:** opasne radnje traže potvrdu, a svaka se upisuje u dnevnik (ko je uradio, kome); administrator ne može da zaključa,
  obriše ili ukloni ulogu **sebi**; ne može se ukloniti **poslednji** administrator; korisnik dobija mejl kada mu
  administrator zaključa nalog, resetuje 2FA ili ga obriše.
- **Fajlovi:** ceo folder `Areas/Admin`, `Security/AdminBootstrapper.cs`, `Security/RequireAdminSecurityAttribute.cs`,
  deo `_LoginPartial.cshtml` (link), u `Program.cs` poziv `AdminBootstrapper.InitializeAsync()`.
- **Aplikacija bez admin panela:** napravi je bez `--admin` (paket `basic` ili `standard`); kasnije se dodaje sa
  `dotnet new identitymvc-add --feature admin` (7.3).

### 5.21 Čuvanje podataka i čišćenje

- Tabele `SecurityEvents` (dnevnik) i `UserSessions` (uređaji) rastu sa svakom prijavom. `DataRetentionService` na svakih
  12 sati briše događaje starije od `AuditRetentionDays` (365) i sesije starije od `SessionRetentionDays` (30).
- Ako zakon ili firma traže duže čuvanje dnevnika, samo povećaj broj dana.

### 5.22 Automatski testovi i CI

- **Šta je to:** projekat `IdentityToMvc.Tests` pokreće **celu aplikaciju u memoriji** (sa SQLite bazom umesto SQL Servera
  i "lažnim" poštanskim sandučetom umesto SMTP-a) i klikće kroz nju kao korisnik: registracija, potvrda mejla, prijava,
  zaključavanje i link za otključavanje, pokušaj preuzimanja tuđeg mejla, odjava drugih uređaja, admin panel, sigurnosna
  zaglavlja, jezici, šifrovanje 2FA tajni.
- **Pokretanje:** u folderu repozitorijuma `dotnet test --project IdentityToMvc.Tests` (ili *Test → Run All Tests* u
  Visual Studio-u). Nije potreban SQL Server ni mejl server.
- **CI:** `.github/workflows/ci.yml` - GitHub posle svakog push-a i za svaki PR proveri prevode, uradi build, pokrene testove i
  proveri da nijedan paket nema poznat ozbiljan bezbednosni propust. Rezultat se vidi na PR-u (zelena kvačica ili crveni X).
- **Kad menjaš kod:** pokreni testove pre nego što pošalješ izmene. Ako dodaš novu funkcionalnost, dodaj i test po uzoru na
  postojeće (`AccountSecurityTests.cs` je dobar primer).

---

## 6. Paketi: osnovno, standardno, kompletno

Postoje dva nivoa prilagođavanja:

1. **Pri pravljenju aplikacije** (šablon, [odeljak 7](#7-nova-aplikacija-jednom-komandom-šablon)) biraš paket i funkcije -
   kod funkcija koje ne izabereš **uopšte ne postoji** u novoj aplikaciji. Ovo je preporučeni način.
2. **Kasnije, u `appsettings.json`**, funkcije koje aplikacija ima mogu privremeno da se isključe prekidačima
   (npr. `"EnableTwoFactor": false`) - bez menjanja koda. Isključene funkcije nestaju iz menija, a adrese vraćaju "404".

### Šta sadrži koji paket

O = osnovno (`--tier basic`), S = standardno (`--tier standard`, podrazumevano), K = kompletno (`--tier full`).
Poslednja kolona je **prekidač** kojim se funkcija dodaje na bilo koji paket (npr. `--tier basic --admin`).

| Funkcija | O | S | K | Prekidač |
|----------|:-:|:-:|:-:|----------|
| Registracija, potvrda mejla, ponovno slanje potvrde | ✅ | ✅ | ✅ | - |
| Prijava i odjava, "Zapamti me" | ✅ | ✅ | ✅ | - |
| Zaboravljena lozinka i reset | ✅ | ✅ | ✅ | - |
| Zaključavanje posle 3 pogrešne lozinke | ✅ | ✅ | ✅ | - |
| Promena lozinke | ✅ | ✅ | ✅ | - |
| Link za otključavanje u mejlu (5.3) | - | ✅ | ✅ | `--unlock-link` |
| Profil - broj telefona (5.5) | - | ✅ | ✅ | `--profile` |
| Promena mejla (5.5) | - | ✅ | ✅ | `--email-change` |
| Lični podaci: preuzimanje i brisanje naloga (5.9) | - | ✅ | ✅ | `--personal-data` |
| Provera procurelih lozinki (5.14) | - | ✅ | ✅ | `--breached-passwords` |
| 2FA, recovery kodovi, "zapamti ovaj uređaj", šifrovane 2FA tajne (5.6) | - | ✅ | ✅ | `--two-factor` |
| Sudo mode (5.10) | - | ✅ | ✅ | `--sudo` |
| Bezbednosni mejlovi, mejl za novi uređaj (5.12) | - | ✅ | ✅ | `--notifications` |
| Uređaji i odjava sa svih uređaja (5.11) | - | ✅ | ✅ | `--devices` |
| Stranica "Bezbednosna aktivnost" (5.12) | - | ✅ | ✅ | `--activity` |
| Automatski testovi (5.22) | - | ✅ | ✅ | `--tests` |
| Passkeys (5.7) | - | - | ✅ | `--passkeys` |
| Admin panel (5.20); uz 2FA ili passkeys - admin mora da ih koristi | - | - | ✅ | `--admin` |
| Google prijava (5.8) | - | - | - | `--google` |
| Facebook prijava (5.8) | - | - | - | `--facebook` |
| Jezik: srpski + engleski / srpski / engleski (5.19) | izbor | izbor | izbor | `--lang both\|sr\|en` |
| Baza: SQL Server / PostgreSQL / SQLite | izbor | izbor | izbor | `--db sqlserver\|postgres\|sqlite` |

- **Osnovno** - interni alati, prototipovi, mali sajtovi: korisnik u nalogu vidi samo *Lozinka*.
- **Standardno** - većina javnih aplikacija (preporuka).
- **Kompletno** - aplikacije sa novcem, zdravstvenim ili poslovnim podacima.

> Za javne aplikacije u Srbiji i EU brisanje i preuzimanje ličnih podataka je praktično zakonska obaveza - uz osnovni
> paket dodaj `--personal-data`.

### Šta je uvek uključeno

Ove zaštite nemaju ekrane i ne smetaju korisniku, pa su u svakom paketu:

| Zaštita | Napomena |
|---------|----------|
| Sigurnosna zaglavlja i CSP (5.15) | Pravila u `SecurityHeadersMiddleware.cs`. |
| `__Host-` kolačići, zaštita formi (antiforgery) | Zahtevaju HTTPS - što je ionako obavezno. |
| Jak heš lozinke, pravila lozinke (5.14) | Nevidljivo korisniku. |
| Bez otkrivanja naloga: isti odgovori, isto vreme prijave, mejlovi u pozadini | 5.1, 5.2 |
| Zaštita od preuzimanja naloga unapred (5.1) | |
| Ograničenje broja zahteva (5.13) | Može da se isključi u `appsettings.json`. |
| Dnevnik događaja i evidencija sesija u bazi | Služe i za "odjavu" koja stvarno važi odmah; stranice za njih su posebne funkcije. |
| Data Protection ključevi u bazi (5.17) | |

### Prekidači u `appsettings.json` (sekcija `Security`)

Za funkcije koje aplikacija ima: `EnableTwoFactor`, `EnablePasskeys`, `RequireRecentAuthentication` (sudo),
`EnableRateLimiting`, `CheckBreachedPasswords`, `SendSecurityNotifications`, `RequireTwoFactorForAdmins`.
Svi su podrazumevano `true`; vidi i [odeljak 9](#9-sva-podešavanja-na-jednom-mestu).

---

## 7. Nova aplikacija jednom komandom (šablon)

Ovaj repozitorijum je istovremeno i **`dotnet new` šablon**. Umesto kopiranja i preimenovanja fajlova, nova aplikacija
se pravi jednom komandom - sa tvojim imenom, izabranim paketom, bazom i jezikom.

### 7.1 Instalacija šablona (jednom na računaru)

Dok šablon nije objavljen (vidi 7.5), instalira se iz repozitorijuma:

```bash
git clone https://github.com/MarkoLazic4/IdentityToMvc.git
dotnet new install ./IdentityToMvc
```

Kada bude objavljen na NuGet-u, dovoljno je: `dotnet new install IdentityToMvc.Templates`.

Posle instalacije postoje dva šablona:

| Šablon | Čemu služi |
|--------|------------|
| `identitymvc` | Pravi **novu aplikaciju**. |
| `identitymvc-add` | Dodaje **jednu funkciju** u aplikaciju koja je već napravljena (vidi 7.3). |

U Visual Studio-u se šablon pojavljuje u *File → New → Project* kao **"ASP.NET Core MVC with Identity (IdentityToMvc)"**,
sa padajućim menijima za paket, bazu, jezik i funkcije.

### 7.2 Pravljenje aplikacije

```bash
dotnet new identitymvc -n Alat --tier basic --lang sr
dotnet new identitymvc -n Prodavnica --tier standard --google --db postgres
dotnet new identitymvc -n Klinika --tier full --lang both
dotnet new identitymvc -n Portal --tier basic --admin --personal-data --tests
```

- `-n` - ime aplikacije. Od njega nastaju folder, projekti (`Prodavnica.Web`, `Prodavnica.Tests`), namespace, imena
  kolačića, ime u aplikaciji za 2FA, ime baze - **ništa ne treba ručno preimenovati**.
- `--tier` - paket (`basic`, `standard`, `full`); bez njega je `standard`.
- `--db` - baza (`sqlserver`, `postgres`, `sqlite`); bez njega je `sqlserver`.
- `--lang` - jezik (`both`, `sr`, `en`); bez njega su oba, srpski podrazumevano.
- ostali prekidači **dodaju** funkcije na paket (tabela u [odeljku 6](#6-paketi-osnovno-standardno-kompletno)).
  Da bi funkcija izostala, izaberi manji paket i dodaj samo ono što ti treba.

Spisak svih opcija: `dotnet new identitymvc --help`.

**Šta dobijaš:** rešenje sa projektom `<Ime>.Web` (i `<Ime>.Tests` ako su testovi uključeni), `README.md` sa spiskom
funkcija koje aplikacija ima i GitHub Actions proverom (`.github/workflows/ci.yml`).

**Pokretanje:**

1. Podesi mejl (SMTP sekcija, vidi 5.16). U Development-u stranica "Proveri mejl" sama prikazuje link za potvrdu,
   pa sve može da se isproba i bez mejl servera.
2. Proveri adresu baze u `<Ime>.Web/appsettings.Development.json` (SQL Server LocalDB, PostgreSQL na `localhost` ili
   SQLite fajl pored aplikacije).
3. `cd <Ime>.Web` i `dotnet run` (ili `F5` u Visual Studio-u). **Baza se sama napravi** iz gotovih migracija
   (`Data/Migrations`) - nije potrebna komanda `dotnet ef`.
4. Ako aplikacija ima admin panel: upiši svoj mejl u `Admin:Emails` (5.20).
5. Dodaj svoje stranice i zaštiti ih ([odeljak 8](#8-autorizacija---kako-zaštititi-sopstvene-stranice)).

### 7.3 Dodavanje funkcije kasnije (`identitymvc-add`)

Ako si napravio osnovnu aplikaciju, a kasnije ti zatreba npr. admin panel - ne moraš ništa da kopiraš ručno.
U folderu rešenja (tamo gde je `.sln`) pokreni:

```bash
dotnet new identitymvc-add --feature admin -n Portal --tier basic --personal-data --tests
```

- `--feature` - funkcija koja se dodaje: `profile`, `email-change`, `personal-data`, `unlock-link`,
  `breached-passwords`, `two-factor`, `sudo`, `passkeys`, `google`, `facebook`, `notifications`, `devices`,
  `activity`, `admin`, `tests`;
- `-n` i ostale opcije - **iste kao kada je aplikacija pravljena** (po njima šablon zna kako izgleda tvoja aplikacija,
  npr. da li admin panel treba da prikazuje 2FA).

Komanda:

1. **fizički iskopira fajlove** te funkcije u projekat (kontrolere, view-ove, ViewModel-e, skripte, testove);
2. napravi fajl **`ADD-<funkcija>.md`** sa spiskom koda koji treba dodati u zajedničke fajlove (`Program.cs`,
   meni, `appsettings.json`...). Svaki korak kaže u koji fajl, iznad ili ispod koje linije, i šta da nalepiš.
   Korak označen *"Only if your app has ..."* preskoči ako tvoja aplikacija nema tu funkciju.

Posle toga: **Build**, pa (ako imaš testove) `dotnet test`. Kada završiš, `ADD-<funkcija>.md` možeš da obrišeš.

> Ovo je isto kao Microsoft-ov "scaffold" za Identity: dobijaš prave fajlove koje posle menjaš kako hoćeš.
> CI ovog repozitorijuma za svaku funkciju automatski prati njen `ADD-<funkcija>.md` na osnovnoj aplikaciji i proverava
> da se sve kompajlira i da testovi prolaze.

### 7.4 Nova verzija šablona

- Kada se šablon ažurira: `git pull` pa ponovo `dotnet new install ./IdentityToMvc --force`
  (ili `dotnet new update` kada bude na NuGet-u).
- **Već napravljene aplikacije se ne menjaju same** - one su tvoj kod. Ako nova verzija donese bezbednosnu ispravku,
  opis u [odeljku 13](#13-šta-je-novo-u-ovoj-verziji) kaže koji fajl i šta da promeniš.

### 7.5 Objavljivanje šablona (kada odlučiš)

Šablon je spreman za pakovanje; objavljivanje je poseban, namerni korak:

```bash
dotnet pack templates/IdentityToMvc.Templates.csproj -o artifacts
```

Nastaje `artifacts/IdentityToMvc.Templates.1.0.0.nupkg` sa oba šablona. Zatim, zavisno od toga ko sme da ga koristi:

| Gde | Ko može da ga koristi | Kako se objavljuje |
|-----|-----------------------|--------------------|
| **nuget.org** (javno) | Bilo ko | `dotnet nuget push artifacts/*.nupkg --api-key <ključ> --source https://api.nuget.org/v3/index.json` (ključ se pravi na nuget.org) |
| **GitHub Packages** (privatno) | Ti i ljudi kojima daš pristup | `dotnet nuget push ... --source https://nuget.pkg.github.com/MarkoLazic4/index.json` (GitHub token) |
| **Samo repozitorijum** | Ko ima pristup repozitorijumu | Ništa - instalira se sa `dotnet new install ./IdentityToMvc` |

Pre svake nove verzije povećaj `<Version>` u `templates/IdentityToMvc.Templates.csproj`.

### 7.6 Aplikacija koja nije napravljena šablonom

Ako već imaš aplikaciju i želiš da joj dodaš ovaj sistem, najlakše je da napraviš novu aplikaciju šablonom sa istim
imenom u privremenom folderu, pa odatle prekopiraš fajlove. Ručni postupak:

1. **Paketi** - u `.csproj` svoje aplikacije dodaj iste `PackageReference` stavke kao u `IdentityToMvc.Web.csproj`
   (Identity.EntityFrameworkCore, EntityFrameworkCore.SqlServer, DataProtection.EntityFrameworkCore, Google/Facebook ako ih koristiš...).
2. **Kopiraj foldere i fajlove:**
   - ceo folder `Areas/User` (i `Areas/Admin` ako želiš admin panel);
   - folderi `Security`, `Services`, `Settings`, `Helpers`, `Localization`, `Resources`;
   - `Data/ApplicationDbContext.cs`, `Data/SecurityEventRecord.cs`, `Data/UserSession.cs` - ili, ako već imaš svoj DbContext,
     neka nasleđuje `IdentityDbContext`, implementira `IDataProtectionKeyContext` i ima tabele `SecurityEvents` i
     `UserSessions` (vidi kako je urađeno u ovom fajlu);
   - `Views/Shared/_LoginPartial.cshtml`, `Views/Shared/_StatusMessage.cshtml`, `Views/Home/StatusCode.cshtml` +
     akcije `HttpStatusCode` i `SetLanguage` iz `HomeController`-a;
   - `wwwroot/css/site.css`, `wwwroot/js/site.js`, `wwwroot/js/passkeys.js`, `wwwroot/js/site.qrcode.js`,
     biblioteke iz `wwwroot/lib` (`bootstrap` 5.3, `bootstrap-icons`, `qrcodejs`, `jquery`, `jquery-validation`, `jquery-validation-unobtrusive`).
3. **Program.cs** - prenesi sve blokove između `var builder = ...` i `builder.Services.AddControllersWithViews();`,
   kao i ceo donji deo (redosled `app.Use...` - vidi [odeljak 4](#4-put-jednog-klika---kako-aplikacija-obrađuje-zahtev)),
   uključujući rutu `areas`.
4. **Layout tvoje aplikacije** (`_Layout.cshtml`) mora da ima:
   - `<partial name="_LoginPartial" />` u gornjoj traci;
   - uključen `site.css`, Bootstrap 5.3 i `bootstrap-icons.min.css` u `<head>`; jQuery, `bootstrap.bundle.min.js`
     i `site.js` na dnu;
   - `@await RenderSectionAsync("Scripts", required: false)` na dnu;
   - prekidač jezika (forma `language-form`) i `<script type="application/json" id="i18n">` sa tekstovima za JavaScript
     (prekopiraj iz `_Layout.cshtml` ovog projekta);
   - **nijednu skriptu direktno u HTML-u bez nonce-a** (vidi 5.15), inače će je CSP blokirati.
5. **`_ViewImports.cshtml`** - dodaj `@using TvojaAplikacija.Security`, `@using TvojaAplikacija.Localization` i
   `@inject IHtmlLocalizer<SharedResource> L` (prekopiraj iz `_ViewImports.cshtml` ovog projekta).
6. **appsettings.json** - prenesi sekcije `SMTP`, `Security`, `Admin` i `Localization`.
7. **Migracije baze** - prekopiraj `Data/Migrations/<tvoja baza>` (ili, ako već imaš svoje migracije, napravi novu:
   `dotnet ef migrations add IdentityToMvc`).
8. **Pokreni Build** i ispravi namespace-ove koje Visual Studio podvuče.

---

## 8. Autorizacija - kako zaštititi sopstvene stranice

Kada dodaš svoje stranice, odlučuješ ko sme da ih vidi.

**Samo prijavljeni korisnici** - dodaj `[Authorize]` iznad kontrolera ili akcije:

```csharp
using Microsoft.AspNetCore.Authorization;

[Authorize]                         // cela "kancelarija" samo za prijavljene
public class OrdersController : Controller
{
    public IActionResult Index() => View();

    [AllowAnonymous]                // izuzetak: ovu stranicu vide svi
    public IActionResult Prices() => View();
}
```

Neprijavljeni korisnik se automatski šalje na `Log in`, a posle prijave vraća na stranicu koju je hteo.

**Uloge (npr. administrator)** - uloga `Admin` se pravi sama pri pokretanju, a prvi administratori se određuju u
`appsettings.json` (`"Admin": { "Emails": [...] }`, vidi 5.20). Ostale uloge (npr. `Urednik`, `Knjigovodja`) pravi i
dodeljuje administrator u **admin panelu** (*Roles* i *Users → detalji korisnika*) - bez programiranja.

Zatim zaštiti stranicu:

```csharp
[Authorize(Roles = "Urednik")]
public class ArticlesController : Controller { ... }

[Authorize(Roles = "Admin,Urednik")]   // bilo koja od dve uloge
public class ReportsController : Controller { ... }
```

Ako praviš svoje **administratorske** stranice, najlakše je da nasleđuju `AdminControllerBase` iz `Areas/Admin` -
tako automatski dobijaju iste zaštite (uloga `Admin`, obavezna 2FA, ograničenje zahteva).

U view-u možeš prikazati nešto samo administratoru: `@if (User.IsInRole("Admin")) { ... }`.

> Kada administrator promeni uloge u panelu, korisniku se osvežava "pečat" naloga, pa nova uloga važi najkasnije za 5 minuta.

**Osetljive radnje u tvojoj aplikaciji** (npr. isplata, brisanje) - dodaj i `[RequireRecentAuthentication]` da se lozinka
traži ponovo (vidi 5.10).

---

## 9. Sva podešavanja na jednom mestu

`appsettings.json` (tajne vrednosti stavljaj u `appsettings.Local.json` ili user-secrets, **nikad u git**):

| Podešavanje | Značenje | Podrazumevano |
|-------------|----------|---------------|
| `ConnectionStrings:Default` | Adresa baze (u Development-u u `appsettings.Development.json`, u produkciji kao tajna/promenljiva `ConnectionStrings__Default`) | - |
| `Database:ApplyMigrationsOnStartup` | Aplikacija pri pokretanju sama napravi/ažurira bazu | `true` u Development-u, inače `false` |
| `SMTP:Host`, `Port`, `EnableSsl` | Mejl server | -, 587, true |
| `SMTP:Username`, `Password` | Nalog za mejl server | - |
| `SMTP:From`, `FromName` | Pošiljalac mejlova | - , IdentityToMvc |
| `GoogleClientId`, `GoogleClientSecret` | Google prijava (bez njih - nema dugmeta) | prazno |
| `FacebookAppId`, `FacebookAppSecret` | Facebook prijava | prazno |
| `Security:EnableTwoFactor` | 2FA i recovery kodovi | true |
| `Security:EnablePasskeys` | Passkey-ovi | true |
| `Security:RequireRecentAuthentication` | Sudo mode | true |
| `Security:EnableRateLimiting` | Ograničenje broja zahteva | true |
| `Security:CheckBreachedPasswords` | Provera procurelih lozinki | true |
| `Security:SendSecurityNotifications` | Mejl upozorenja | true |
| `Security:MaxPasskeysPerUser` | Najviše passkey-ova po korisniku | 10 |
| `Security:PasskeyServerDomain` | Domen za passkey-ove (npr. `mojsajt.rs`); prazno = domen iz adrese | prazno |
| `Security:KnownProxies` | IP adrese reverse proxy-ja kojima se veruje | [] |
| `Security:RequireTwoFactorForAdmins` | Admin panel samo uz 2FA ili passkey | true |
| `Security:AuditRetentionDays` | Koliko dana se čuva dnevnik događaja | 365 |
| `Security:SessionRetentionDays` | Koliko dana se čuvaju zapisi o sesijama | 30 |
| `Security:DataProtectionCertificatePath`, `...Password` | Sertifikat (.pfx) koji šifruje ključeve | prazno |
| `Admin:Emails` | Mejlovi koji postaju administratori kad se potvrde | [] |
| `Localization:DefaultCulture` | Podrazumevani jezik: `sr-Latn-RS` ili `en` | sr-Latn-RS |

Vrednosti koje se menjaju u kodu (`Program.cs`, osim ako nije drugačije navedeno):

| Šta | Gde | Vrednost |
|-----|-----|----------|
| Pravila lozinke | `options.Password...` + ViewModel-i | 8+, A-z, 0-9, simbol |
| Zaključavanje | `options.Lockout...` | 3 pokušaja, 10 min |
| Trajanje prijave | `ExpireTimeSpan` | 1 sat (produžava se) |
| Trajanje linkova iz mejla | `TokenLifespan` | 3 sata |
| Provera pečata naloga | `ValidationInterval` | 5 minuta |
| Heš lozinke | `IterationCount` | 600.000 |
| Sudo prozor | `RecentAuthentication.cs` → `Window` | 15 minuta |
| Rate limit brojevi | `RateLimitPolicies.cs` | 20/min, 5/10 min |
| Keš provere sesije | `SessionService.cs` | 30 sekundi |
| Jezici | `LocalizationSetup.cs` | srpski (latinica), engleski |

---

## 10. Pre puštanja u rad (produkcija)

- [ ] Sajt radi isključivo preko **HTTPS-a** (sertifikat, npr. Let's Encrypt).
- [ ] Okruženje je **Production** (`ASPNETCORE_ENVIRONMENT=Production`) - tada se ne prikazuje link za potvrdu na ekranu i uključuje se HSTS.
- [ ] Lozinke i ključevi su u **tajnim podešavanjima** servera (environment variables, Azure Key Vault...), ne u `appsettings.json`.
  Primer imena promenljive: `SMTP__Password`, `ConnectionStrings__Default` (dve donje crte umesto dvotačke).
- [ ] **SMTP radi** - pošalji sebi test (registracija ili "Forgot password").
- [ ] Migracije su primenjene na produkcionu bazu (`dotnet ef database update` ili SQL skripta: `dotnet ef migrations script`).
- [ ] Ako postoji reverse proxy - upisan je u `Security:KnownProxies`.
- [ ] Ako se koriste passkey-ovi na više poddomena - podešen `Security:PasskeyServerDomain`.
- [ ] Google/Facebook: u njihovim konzolama upisana je adresa povratka `https://tvojsajt/signin-google` odnosno `/signin-facebook`.
- [ ] Logovi se čuvaju i prate (audit log - traži `Security audit:`).
- [ ] Podešen je **sertifikat za Data Protection ključeve** (`Security:DataProtectionCertificatePath`).
- [ ] U `Admin:Emails` je pravi mejl administratora, a administrator je uključio 2FA ili passkey.
- [ ] Izabran je podrazumevani jezik (`Localization:DefaultCulture`).
- [ ] CI na GitHub-u je zelen (testovi prolaze).
- [ ] Tekst na stranici *Privacy* je prilagođen tvojoj aplikaciji.

---

## 11. Česti problemi i rešenja

| Problem | Uzrok i rešenje |
|---------|-----------------|
| Ne mogu da se prijavim posle registracije | Mejl nije potvrđen. U Development-u klikni link na stranici "Check your email"; inače proveri SMTP podešavanja i log. |
| Mejlovi ne stižu | Proveri `SMTP` sekciju (port 587 + `EnableSsl: true` za Gmail/Outlook; za Gmail treba "App password"). Greške su u logu: `Failed to send email`. |
| Prijava ne radi na `http://` | Kolačići `__Host-` rade samo preko HTTPS-a. Pokreni profil `https` u Visual Studio-u. |
| Passkey dugme ne radi / greška | Passkey zahteva HTTPS ili `localhost` i uređaj sa otiskom/licem/PIN-om. Proveri i `PasskeyServerDomain`. |
| Stranica traži lozinku "bez razloga" | To je sudo mode (prošlo je 15+ minuta od prijave). Isključuje se sa `RequireRecentAuthentication: false`. |
| "429 Too many requests" | Previše pokušaja sa iste IP adrese - sačekaj. Ako se dešava svima iza proxy-ja, podesi `KnownProxies`. |
| Moja skripta ne radi, u konzoli browsera piše "Content Security Policy" | Skripta je direktno u HTML-u ili sa drugog sajta. Premesti je u `.js` fajl u `wwwroot/js`, dodaj `nonce="@Context.GetCspNonce()"`, ili dozvoli domen u `SecurityHeadersMiddleware.cs`. |
| Posle restarta su svi odjavljeni | Tabela `DataProtectionKeys` ne postoji - napravi i primeni migraciju. |
| Lozinka se odbija sa "appeared in a data breach" | Lozinka je poznata iz curenja podataka - izaberi drugu. (Isključuje se sa `CheckBreachedPasswords: false`.) |
| Nema dugmeta za Google/Facebook | Ključevi nisu upisani u podešavanja (vidi 5.8). |
| Admin panel ne postoji u meniju | Mejl nije u `Admin:Emails`, nije potvrđen, ili je nalog napravljen pre upisa - restartuj aplikaciju. Posle toga se odjavi i prijavi. |
| Admin panel stalno vraća na stranicu za 2FA | Administrator mora da ima 2FA ili passkey (`RequireTwoFactorForAdmins`). Uključi 2FA i pokušaj ponovo. |
| Neki tekst je na engleskom iako je izabran srpski | Tekst nema prevod. Pokreni `python3 tools/extract_keys.py` i dodaj prevod u `SharedResource.sr-Latn.resx` (5.19). |
| Greška "Invalid object name 'SecurityEvents'" ili "'UserSessions'" | Nova migracija nije napravljena/primenjena (odeljak 10). |
| Korisnik je odjavljen odmah posle prijave na drugom mestu | Neko je na stranici *Devices* ugasio tu sesiju ili je administrator odjavio korisnika - pogledaj *Security activity*. |
| `dotnet new identitymvc-add` javlja da bi promenio postojeće fajlove | Funkcija (ili njen deo) već postoji u aplikaciji. Proveri da li si pokrenuo komandu sa istim opcijama kao pri pravljenju aplikacije. |
| Build greške posle `identitymvc-add` | Nisu dodati svi koraci iz `ADD-<funkcija>.md`, ili je dodat korak "Only if ..." za funkciju koju aplikacija nema. |
| Greška "The model for context has pending changes" ili dupla tabela | Stare, ručno pravljene migracije iz ranije verzije su pored novih gotovih. Obriši svoje stare migracije (i bazu na razvojnom računaru) i ostavi `Data/Migrations/<baza>`. |
| `dotnet new identitymvc` ne postoji | Šablon nije instaliran - vidi 7.1. |
| Build prijavljuje greške posle prenosa koda | Najčešće namespace - zameni `IdentityToMvc.Web` imenom svog projekta u svim fajlovima. |

---

## 12. Kako da proveriš da sve radi

Posle prenosa u novu aplikaciju prođi ovu listu (traje oko 10 minuta):

1. Registruj nalog → potvrdi mejl (link u mejlu ili na ekranu u Development-u) → prijavi se.
2. Tri puta upiši pogrešnu lozinku → treba da se pojavi "Account temporarily locked".
3. "Forgot password?" → link iz mejla → nova lozinka → prijava radi.
4. Manage → Profile: sačuvaj broj telefona → zelena poruka.
5. Manage → Password: promeni lozinku → poruka + mejl upozorenja.
6. (Ako je uključeno) Manage → Two-factor: skeniraj QR kod, upiši kod → dobiješ 10 recovery kodova. Odjavi se i prijavi - traži kod.
7. (Ako je uključeno) Manage → Passkeys: dodaj passkey → odjavi se → "Log in with a passkey".
8. Prijavi se na drugom browseru → na prvom Manage → *Devices* → "Sign out everywhere" → drugi browser je odmah odjavljen.
9. Manage → Personal data: preuzmi JSON; napravi probni nalog i obriši ga.
10. Otvori nepostojeću adresu (npr. `/nesto`) → lepa stranica 404.
11. Uključi tamnu temu (ikonica meseca gore desno) → izgled se menja i pamti.
12. Klikni **SR / EN** → tekstovi se menjaju; osveži stranicu → jezik se pamti.
13. Manage → *Devices* → vidiš oba browsera iz koraka 8; odjavi jedan dugmetom pored njega → on je odmah odjavljen.
14. Manage → *Security activity* → vidiš prijave i pogrešne lozinke iz koraka 2.
15. Prijavi se kao administrator (mejl iz `Admin:Emails`, sa 2FA) → *Admin panel* → nađi probni nalog → zaključaj ga →
    probni korisnik ne može da se prijavi; otključaj ga.
16. U terminalu: `dotnet test --project <Ime>.Tests` → svi testovi prolaze.

Ako sve prolazi - sistem je spreman, a ti možeš da se posvetiš stvarnoj funkcionalnosti svoje aplikacije.

---

## 13. Šta je novo u ovoj verziji

**Popravljeni bezbednosni propusti**

| Propust | Šta je mogao napadač | Kako je rešeno |
|---------|----------------------|----------------|
| Preuzimanje naloga unapred | Da registruje tuđi mejl sa svojom lozinkom i čeka da vlasnik potvrdi mejl ili se prijavi preko Google-a. | Nepotvrđen nalog se zamenjuje novom registracijom; aktivacija uvek traži novu lozinku; spoljne prijave se ne povezuju same (5.1, 5.8). |
| Otkrivanje naloga po vremenu | Da po brzini prijave zaključi koji mejlovi imaju nalog. | Jednako vreme odgovora (5.2). |
| Otkrivanje naloga pri registraciji | Da vidi grešku "mejl je zauzet". | Isti odgovor za sve, vlasnik dobija mejl (5.1). |
| 2FA tajne u bazi kao običan tekst | Sa kopijom baze da pravi važeće 2FA kodove. | Šifrovanje i heširanje (5.17). |
| Zloupotreba zaključavanja | Da stalno drži tuđi nalog zaključanim. | Link za otključavanje i prijava passkey-om (5.3). |
| Reset lozinke skidao je i zaključavanje administratora | Korisnik kog je administrator zaključao mogao je sam da se "otključa" preko "Forgot password". | Reset lozinke skida samo zaključavanje zbog pogrešnih lozinki (`AccountController.cs`, akcija `ResetPassword`). |

**Šablon:** nova aplikacija jednom komandom (`dotnet new identitymvc`) sa izborom paketa, baze (SQL Server, PostgreSQL,
SQLite), jezika i funkcija; kasnije dodavanje funkcije (`dotnet new identitymvc-add`); gotove migracije; NuGet paket
spreman za objavljivanje (odeljak 7).

**Nove mogućnosti:** uređaji i odjava pojedinačnog uređaja (5.11), bezbednosna aktivnost i dnevnik u bazi (5.12),
mejl pri prijavi sa novog uređaja (5.11), lokalizacija srpski/engleski (5.19), admin panel (5.20), automatsko čišćenje
starih podataka (5.21), automatski testovi i CI (5.22), šifrovanje ključeva sertifikatom (5.17).

**Posle preuzimanja ove verzije:** ako si ranije sam pravio migracije, obriši ih - repozitorijum sada ima gotove
(`Data/Migrations/SqlServer`), a u Development-u se baza sama ažurira. Upiši svoj mejl u `Admin:Emails`.

**Preostali rizik (poznat i prihvaćen):** ako napadač registruje tuđi mejl, vlasnik dobije mejl za potvrdu. Ako vlasnik
klikne taj link u roku od 3 sata, **potvrdiće nalog koji je napravio napadač** (sa napadačevom lozinkom). Zato mejl za
potvrdu jasno kaže "ako niste vi pravili nalog, ignorišite ovaj mejl", a vlasnik uvek može da preuzme nalog preko
"Forgot password", čime se gase sve napadačeve sesije.
