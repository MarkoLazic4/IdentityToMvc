# Uputstvo: gotov sistem za prijavu i naloge (IdentityToMvc)

Ovaj projekat je **gotov "modul" za prijavu korisnika** koji se može preneti u bilo koju buduću
ASP.NET Core MVC aplikaciju. Svaka aplikacija mora da zna *ko* je korisnik (autentifikacija) i
*šta sme da radi* (autorizacija) - ovde je to već napravljeno, provereno i obezbeđeno.

Uputstvo je pisano tako da ga može pratiti i neko ko se ne bavi programiranjem svakodnevno.
Stručni izrazi su objašnjeni u [rečniku](#1-rečnik) na početku.

**Sadržaj**

1. [Rečnik](#1-rečnik)
2. [Velika slika - šta ovaj sistem radi](#2-velika-slika---šta-ovaj-sistem-radi)
3. [Mapa projekta - šta se gde nalazi](#3-mapa-projekta---šta-se-gde-nalazi)
4. [Put jednog klika - kako aplikacija obrađuje zahtev](#4-put-jednog-klika---kako-aplikacija-obrađuje-zahtev)
5. [Funkcionalnosti jedna po jedna](#5-funkcionalnosti-jedna-po-jedna)
6. [Paketi: osnovno, standardno, kompletno](#6-paketi-osnovno-standardno-kompletno)
7. [Kako preneti sistem u novu aplikaciju](#7-kako-preneti-sistem-u-novu-aplikaciju)
8. [Autorizacija - kako zaštititi sopstvene stranice](#8-autorizacija---kako-zaštititi-sopstvene-stranice)
9. [Sva podešavanja na jednom mestu](#9-sva-podešavanja-na-jednom-mestu)
10. [Pre puštanja u rad (produkcija)](#10-pre-puštanja-u-rad-produkcija)
11. [Česti problemi i rešenja](#11-česti-problemi-i-rešenja)
12. [Kako da proveriš da sve radi](#12-kako-da-proveriš-da-sve-radi)

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
| **Migracija** | "Recept" koji pravi ili menja tabele u bazi. Pravi se jednom komandom (vidi [odeljak 7](#7-kako-preneti-sistem-u-novu-aplikaciju)). |
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

**Šta korisnik može da uradi:**

| Za neprijavljene | Za prijavljene (Manage account) |
|------------------|---------------------------------|
| Registracija + potvrda mejla | Profil (broj telefona) |
| Prijava lozinkom | Promena mejla |
| Prijava passkey-om | Promena / postavljanje lozinke |
| Prijava preko Google-a / Facebook-a | Dvofaktorska autentifikacija (2FA) |
| 2FA kod ili recovery kod pri prijavi | Passkey-ovi |
| Zaboravljena lozinka / reset | Spoljne prijave (Google/Facebook) |
| Ponovno slanje potvrde mejla | Odjava sa svih drugih uređaja |
| | Preuzimanje i brisanje ličnih podataka |

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
| `Controllers/AccountController.cs` | **Recepcija**: registracija, potvrda mejla, prijava (lozinka, 2FA, recovery kod, passkey, Google/Facebook), odjava, zaboravljena i reset lozinke, zaključan nalog. |
| `Controllers/ManageController.cs` | **Kancelarija naloga**: profil, mejl, lozinka, 2FA, recovery kodovi, passkey-ovi, spoljne prijave, lični podaci, odjava sa svih uređaja, potvrda identiteta (sudo). |
| `ViewModels/Account/*.cs` | "Formulari" za stranice recepcije (koja polja i pravila). |
| `ViewModels/Manage/*.cs` | "Formulari" za stranice naloga. |
| `Views/Account/*.cshtml` | Izgled stranica recepcije (Login, Register, ForgotPassword...). |
| `Views/Manage/*.cshtml` | Izgled stranica naloga (Index = profil, Email, ChangePassword, Passkeys...). |
| `Views/Manage/_ManageLayout.cshtml` + `_ManageNav.cshtml` | Okvir i bočni meni stranica naloga. |
| `Views/Shared/_StatusMessage.cshtml` | Zelena/crvena poruka ("Sačuvano" / "Greška"). |
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
| `SecurityNotifier.cs` | Šalje mejl upozorenja i upisuje audit log. |

### Ostali folderi

| Putanja | Uloga |
|---------|-------|
| `Services/EmailService.cs` | Šalje mejl preko SMTP-a. |
| `Services/EmailQueue.cs` | Red za mejlove - šalju se u pozadini. |
| `Services/EmailTemplates.cs` | Izgled mejlova (HTML šabloni). |
| `Settings/SmtpSettings.cs` | Opis SMTP podešavanja (server, port, korisnik...). |
| `Helpers/AuthenticatorHelper.cs` | Pravi ključ i QR kod za aplikaciju na telefonu (2FA). |
| `Helpers/TokenEncoder.cs` | Pakuje tokene u linkove i bezbedno ih raspakuje. |
| `Data/ApplicationDbContext.cs` | Veza sa bazom (tabele korisnika + ključevi). |
| `Controllers/HomeController.cs` | Početna, Privacy, stranice grešaka (404, 429...). |
| `Views/Shared/_Layout.cshtml` | Zajednički okvir svih stranica. |
| `Views/Shared/_LoginPartial.cshtml` | Desni deo gornje trake: "Log in / Sign up" ili meni prijavljenog korisnika. |
| `wwwroot/css/site.css` | Boje, tema (svetla/tamna), izgled kartica i dugmadi. |
| `wwwroot/js/site.js` | Tema, prikaži/sakrij lozinku, jačina lozinke, kopiranje, potvrde. |
| `wwwroot/js/passkeys.js` | Komunikacija browsera sa otiskom prsta / Face ID-om. |
| `wwwroot/js/site.qrcode.js` | Crta QR kod za 2FA. |
| `wwwroot/lib/` | Tuđe biblioteke: Bootstrap (izgled), Bootstrap Icons (ikonice), jQuery i validacija, qrcodejs. |

---

## 4. Put jednog klika - kako aplikacija obrađuje zahtev

Kada korisnik klikne "Log in", zahtev prolazi kroz niz "punktova" definisanih u `Program.cs`
(donji deo fajla, posle `var app = builder.Build();`), **tačno ovim redom**:

1. **`UseForwardedHeaders`** - ako ispred aplikacije stoji reverse proxy, saznaje pravu IP adresu korisnika.
2. **`UseExceptionHandler` / `UseHsts`** (samo u produkciji) - lepa stranica greške; browseru se kaže "uvek koristi HTTPS".
3. **`SecurityHeadersMiddleware`** - lepi sigurnosna zaglavlja i pravi jednokratni *nonce* za skripte.
4. **`UseStatusCodePagesWithReExecute`** - greške 404/429 prikazuje kao lepe stranice.
5. **`UseHttpsRedirection`** - prebacuje `http://` na `https://`.
6. **`UseRouting`** - pronalazi koji kontroler i koja akcija odgovaraju adresi.
7. **`UseRateLimiter`** - proverava da ista IP adresa nije poslala previše zahteva.
8. **`UseAuthentication`** - čita kolačić i utvrđuje *ko* je korisnik.
9. **`UseAuthorization`** - proverava *da li sme* (npr. `[Authorize]` na `ManageController`).
10. **Kontroler i akcija** - izvršava se logika, pa se prikazuje stranica (View).

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
- **Bezbednost:** stranice ne otkrivaju da li mejl već postoji (isti odgovor za sve).
- **Isključivanje potvrde mejla:** u `Program.cs` postaviti `RequireConfirmedAccount` i `RequireConfirmedEmail` na `false` -
  korisnik se tada odmah prijavljuje posle registracije. (Ne preporučuje se za javne sajtove.)

### 5.2 Prijava i odjava

- **Korisnik vidi:** `Log in` stranicu - mejl, lozinka, "Remember me", link za zaboravljenu lozinku.
- **Iza scene:** `AccountController.Login` poziva Identity (`PasswordSignInAsync`). Ako je sve u redu, browser dobija
  kolačić `__Host-IdentityToMvc.Auth` koji važi 1 sat i produžava se dok je korisnik aktivan.
  Ako korisnik ima 2FA, šalje se na stranicu za kod. Odjava (`Logout`) briše kolačić.
- **Fajlovi:** `AccountController` (`Login`, `Logout`), `Views/Account/Login.cshtml`, `Views/Shared/_LoginPartial.cshtml`.
- **Posle prijave** korisnik se vraća na stranicu na koju je hteo da ode (`returnUrl`), ali **samo ako je adresa na istom sajtu** -
  zaštita od preusmeravanja na lažne sajtove.

### 5.3 Zaključavanje naloga (lockout)

- **Korisnik vidi:** posle **3 pogrešne lozinke** stranicu "Account temporarily locked". Zaključavanje traje **10 minuta**.
  Vlasnik naloga dobija mejl upozorenja.
- **Gde se broje promašaji:** prijava lozinkom, 2FA kod, "Confirm it's you" (sudo), brisanje naloga.
- **Otključavanje:** automatski posle 10 minuta, ili odmah uspešnim resetom lozinke.
- **Podešavanje:** `Program.cs` → `options.Lockout.MaxFailedAccessAttempts = 3;` i `DefaultLockoutTimeSpan = TimeSpan.FromMinutes(10);`

### 5.4 Zaboravljena lozinka i reset

- **Korisnik vidi:** "Forgot password?" → unese mejl → dobije link → izabere novu lozinku.
- **Iza scene:** `ForgotPassword` šalje mejl samo ako nalog postoji i mejl je potvrđen, ali korisniku **uvek** prikazuje istu
  poruku (napadač ne može da sazna koji mejlovi postoje). Link važi **3 sata**. Posle reseta se gase sve ostale sesije
  (promeni se "pečat") i skida se zaključavanje.
- **Fajlovi:** `AccountController` (`ForgotPassword`, `ResetPassword`...), `Views/Account/ForgotPassword.cshtml`,
  `ResetPassword.cshtml`, `ForgotpasswordConfirmation.cshtml`, `ResetPasswordConfirmation.cshtml`.

### 5.5 Profil, promena lozinke i mejla

- **Profil** (`Manage/Index`): broj telefona + dugme "Sign out everywhere".
- **Lozinka** (`Manage/ChangePassword`): traži staru i novu lozinku. Ako korisnik nema lozinku (ušao je preko Google-a),
  prikazuje se `SetPassword`. Posle promene: ostale sesije se gase, stiže mejl upozorenja.
- **Mejl** (`Manage/Email`): novi mejl dobija link za potvrdu; **stari mejl dobija upozorenje**. Mejl se menja tek
  kada se klikne link, i to samo ako je prijavljen isti korisnik koji je tražio promenu.
- **Fajlovi:** `ManageController` (`Index`, `ChangePassword`, `SetPassword`, `Email`, `ChangeEmail`, `SendVerificationEmail`,
  `ConfirmEmailChange`) i odgovarajući view-ovi u `Views/Manage`.

### 5.6 Dvofaktorska autentifikacija (2FA) i recovery kodovi

- **Korisnik vidi:** Manage → *Two-factor authentication* → "Add authenticator app" → skenira QR kod telefonom →
  upiše šestocifreni kod → dobije **10 recovery kodova** (može da ih kopira ili preuzme kao `.txt`).
  Od tada se pri prijavi traži kod iz aplikacije. Opcija "Remember this device" preskače kod na tom uređaju.
- **Iza scene:** `AuthenticatorHelper` pravi tajni ključ i adresu za QR kod; `site.qrcode.js` ga crta; Identity proverava
  kodove. Recovery kodovi važe po jednom.
- **Fajlovi:** `ManageController` (`TwoFactorAuthentication`, `EnableAuthenticator`, `Disable2fa`, `ResetAuthenticator`,
  `GenerateRecoveryCodes`, `ShowRecoveryCodes`, `ForgetBrowser`), `AccountController` (`LoginWith2fa`,
  `LoginWithRecoveryCode`), view-ovi sa istim imenima, `Helpers/AuthenticatorHelper.cs`, `wwwroot/js/site.qrcode.js`,
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
- **Fajlovi:** `ManageController` (`Passkeys`, `PasskeyCreationOptions`, `AddPasskey`, `RemovePasskey`),
  `AccountController` (`PasskeyRequestOptions`, `LoginWithPasskey`), `Views/Manage/Passkeys.cshtml`,
  `ViewModels/Manage/PasskeysViewModel.cs`, `wwwroot/js/passkeys.js`, deo `Login.cshtml`.
  U `Program.cs`: `options.Stores.SchemaVersion = IdentitySchemaVersions.Version3;` i blok `Configure<IdentityPasskeyOptions>`.
- **Isključivanje:** `"EnablePasskeys": false`.

### 5.8 Spoljne prijave (Google, Facebook)

- **Korisnik vidi:** dugmad "Log in with Google/Facebook" na Login i Sign up stranicama, i stranicu *External logins* u nalogu.
- **Uključivanje:** upiši ključeve u `appsettings.Local.json` (ili user-secrets):
  `GoogleClientId`, `GoogleClientSecret`, `FacebookAppId`, `FacebookAppSecret`.
  Ključeve dobijaš na Google Cloud Console / Meta for Developers. **Ako ključ nije upisan, dugme se ne prikazuje.**
- **Bezbednost:** i posle Google prijave traži se 2FA ako ga korisnik ima; ne može se ukloniti poslednji način prijave.
- **Fajlovi:** `AccountController` (`ExternalLogin`, `ExternalLoginCallback`, `ExternalLoginConfirmation`),
  `ManageController` (`ExternalLogins`, `LinkLogin`, `LinkLoginCallback`, `RemoveExternalLogin`),
  `Views/Account/ExternalLogin.cshtml`, `Views/Manage/ExternalLogins.cshtml`, `Views/Shared/_ExternalLoginButtons.cshtml`.
- **Drugi provajderi** (Microsoft, GitHub...): dodaju se u `Program.cs` na isti način kao Google (poseban paket).
  Ako dodaješ novi provajder, dodaj njegovu adresu i u `form-action` u `SecurityHeadersMiddleware.cs`.

### 5.9 Lični podaci i brisanje naloga (GDPR)

- **Korisnik vidi:** Manage → *Personal data* → "Download" (JSON fajl sa svim podacima) ili "Delete account"
  (traži lozinku i potvrdu).
- **Fajlovi:** `ManageController` (`PersonalData`, `DownloadPersonalData`, `DeletePersonalData`), view-ovi sa istim imenima.
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
- **Fajlovi:** `Security/RecentAuthentication.cs`, `ManageController` (`ConfirmIdentity`), `Views/Manage/ConfirmIdentity.cshtml`,
  `ViewModels/Manage/ConfirmIdentityViewModel.cs`.
- **Isključivanje:** `"RequireRecentAuthentication": false`. **Dodavanje na tvoju stranicu:** stavi `[RequireRecentAuthentication]` iznad akcije.

### 5.11 Odjava sa svih uređaja

- **Korisnik vidi:** Manage → Profile → "Sign out everywhere".
- **Kako radi:** menja se "pečat" naloga (security stamp). Svi ostali kolačići prestaju da važe u roku od **5 minuta**,
  a "zapamćeni uređaji" za 2FA se zaboravljaju. Trenutna sesija ostaje.
- **Isto se automatski dešava** posle promene lozinke, reseta lozinke, uključivanja/isključivanja 2FA i sličnih izmena -
  a `RefreshSessionOnSecurityStampChangeFilter` pazi da tebe pri tome ne izbaci.

### 5.12 Bezbednosna obaveštenja i audit log

- **Korisnik dobija mejl** kada se: promeni/resetuje/postavi lozinka, traži ili izvrši promena mejla (ide na *stari* mejl),
  uključi/isključi 2FA, resetuje authenticator ključ, generišu novi recovery kodovi, doda/ukloni spoljna prijava ili passkey,
  izvrši odjava sa svih uređaja, zaključa nalog, obriše nalog. U mejlu su vreme, IP adresa i uređaj.
- **Audit log:** svaki događaj se upisuje u log u obliku
  `Security audit: PasswordChanged for user <id> from <IP> (<uređaj>)`.
  Logovi se mogu slati u alat za praćenje (Seq, Application Insights, ELK...).
- **Fajlovi:** `Security/SecurityNotifier.cs` (spisak događaja i tekstovi), `Services/EmailTemplates.cs` (`SecurityNotification`).
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
- **Trajanje linkova iz mejla:** 3 sata (`TokenLifespan` u `Program.cs`).
- **Provera "pečata" naloga:** na 5 minuta (`ValidationInterval` u `Program.cs`).

### 5.18 Izgled

- **Tema:** boje su na vrhu `wwwroot/css/site.css` (`--app-primary`, `--app-accent`...). Promeni te vrednosti i cela
  aplikacija dobija novi izgled - posebno za svetlu (`[data-bs-theme="light"]`) i tamnu (`[data-bs-theme="dark"]`) temu.
- **Ime i logo:** `Views/Shared/_Layout.cshtml` (tekst "IdentityToMvc" i ikonica u gornjoj traci).
- **Tekstovi na stranicama** su na engleskom i nalaze se direktno u `.cshtml` fajlovima i porukama u kontrolerima -
  za prevod na srpski menjaj tekst na tim mestima.
- **Biblioteke:** Bootstrap 5.3 (raspored, dugmad), Bootstrap Icons (ikonice - spisak na icons.getbootstrap.com).

---

## 6. Paketi: osnovno, standardno, kompletno

Najjednostavniji način da prilagodiš sistem aplikaciji: **ne briši kod, već isključi funkcije u `appsettings.json`**.
Isključene funkcije nestaju iz menija, a njihove adrese vraćaju "404".

### Osnovni paket - interne i jednostavne aplikacije

Registracija, potvrda mejla, prijava, odjava, zaboravljena lozinka, profil, promena lozinke i mejla, lični podaci,
zaključavanje posle 3 promašaja, sigurnosna zaglavlja.

```json
"Security": {
  "EnableTwoFactor": false,
  "EnablePasskeys": false,
  "RequireRecentAuthentication": false,
  "EnableRateLimiting": false,
  "CheckBreachedPasswords": false,
  "SendSecurityNotifications": false
}
```

### Standardni paket - većina javnih aplikacija (preporuka)

Sve iz osnovnog + 2FA, recovery kodovi, rate limiting, provera procurelih lozinki, mejl upozorenja.

```json
"Security": {
  "EnableTwoFactor": true,
  "EnablePasskeys": false,
  "RequireRecentAuthentication": false,
  "EnableRateLimiting": true,
  "CheckBreachedPasswords": true,
  "SendSecurityNotifications": true
}
```

### Kompletni paket - aplikacije sa novcem, zdravstvenim ili poslovnim podacima

Sve funkcije uključene (ovo je podrazumevano stanje).

```json
"Security": {
  "EnableTwoFactor": true,
  "EnablePasskeys": true,
  "RequireRecentAuthentication": true,
  "EnableRateLimiting": true,
  "CheckBreachedPasswords": true,
  "SendSecurityNotifications": true
}
```

### Šta je uvek uključeno (ne može se isključiti prekidačem)

| Funkcija | Zašto je uvek uključena / kako se ipak menja |
|----------|---------------------------------------------|
| Zaključavanje posle promašaja | Osnovna zaštita. Broj pokušaja se menja u `Program.cs`. |
| Sigurnosna zaglavlja i CSP | Nemaju cenu za korisnika. Pravila se menjaju u `SecurityHeadersMiddleware.cs`. |
| `__Host-` kolačići | Zahtevaju HTTPS - što je ionako obavezno za produkciju. |
| Jak heš lozinke | Nevidljiv korisniku. |
| Google/Facebook | Uključuju se samo upisivanjem ključeva (vidi 5.8). |
| Potvrda mejla | Menja se u `Program.cs` (vidi 5.1). |

### Kada ipak ukloniti kod?

Samo ako baš ne želiš da kod postoji u projektu. Za svaku funkciju u [odeljku 5](#5-funkcionalnosti-jedna-po-jedna) piše
koje akcije, view-ovi i fajlovi joj pripadaju. Postupak: obriši view-ove i fajlove te funkcije, obriši njene akcije iz
kontrolera, obriši njen red u `_ManageNav.cshtml` i registraciju u `Program.cs`, pa pokreni **Build** - Visual Studio će
podvući sve što je još upućeno na obrisani kod.

---

## 7. Kako preneti sistem u novu aplikaciju

### Opcija A (preporučeno): nova aplikacija počinje od ovog projekta

Ovo je najlakše i najsigurnije - dobijaš sve provereno i odmah radi.

1. **Kopiraj ceo repozitorijum** u novi folder (ili na GitHub-u napravi fork; ako repozitorijum označiš kao
   *Template repository* u Settings, dobijaš i dugme *Use this template*).
2. **Promeni ime aplikacije.** U Visual Studio-u: *Edit → Find and Replace → Replace in Files* (`Ctrl+Shift+H`):
   - `IdentityToMvc.Web` → `TvojaAplikacija.Web` (namespace u svim `.cs` i `.cshtml` fajlovima);
   - preimenuj fajlove `IdentityToMvc.sln` i `IdentityToMvc.Web.csproj` i folder `IdentityToMvc.Web`;
   - tekst `IdentityToMvc` se pojavljuje još na ovim mestima - promeni ga u ime tvoje aplikacije:
     - `Program.cs`: imena kolačića (`__Host-IdentityToMvc.Auth`, `.Xsrf`, `.TempData`) i `SetApplicationName("IdentityToMvc")`;
     - `Security/RecentAuthentication.cs`: kolačić `__Host-IdentityToMvc.Reauth`;
     - `Helpers/AuthenticatorHelper.cs`: ime koje se prikazuje u aplikaciji na telefonu;
     - `appsettings.json`: `FromName` u SMTP sekciji;
     - `Views/Shared/_Layout.cshtml`: naslov i ime u gornjoj traci, link ka GitHub-u u podnožju.
3. **Podesi bazu** u `appsettings.Local.json`:
   ```json
   {
     "ConnectionStrings": {
       "Default": "Server=(localdb)\\MSSQLLocalDB;Database=TvojaAplikacija;Trusted_Connection=True;TrustServerCertificate=True"
     }
   }
   ```
4. **Napravi bazu** (jednom). U terminalu, u folderu projekta:
   ```bash
   dotnet tool install --global dotnet-ef      # samo prvi put na računaru
   dotnet ef migrations add InitialIdentitySchema -o Data/Migrations
   dotnet ef database update
   ```
   Ili u Visual Studio-u (*Tools → NuGet Package Manager → Package Manager Console*):
   `Add-Migration InitialIdentitySchema -OutputDir Data/Migrations`, pa `Update-Database`.
5. **Podesi mejl** (SMTP sekcija, vidi 5.16) i **izaberi paket** (odeljak 6).
6. **Pokreni** (`F5` u Visual Studio-u ili `dotnet run`) i otvori `https://localhost:.../User/Account/Register`.
7. **Dodaj svoje stranice** (novi kontroleri u folderu `Controllers`, view-ovi u `Views`) i zaštiti ih (odeljak 8).

### Opcija B: dodavanje u postojeću aplikaciju

Ako već imaš aplikaciju i želiš da joj dodaš ovaj sistem:

1. **Paketi** - u `.csproj` svoje aplikacije dodaj iste `PackageReference` stavke kao u `IdentityToMvc.Web.csproj`
   (Identity.EntityFrameworkCore, EntityFrameworkCore.SqlServer, DataProtection.EntityFrameworkCore, Google/Facebook ako ih koristiš...).
2. **Kopiraj foldere i fajlove:**
   - ceo folder `Areas/User`;
   - folderi `Security`, `Services`, `Settings`, `Helpers`;
   - `Data/ApplicationDbContext.cs` - ili, ako već imaš svoj DbContext, neka nasleđuje `IdentityDbContext` i implementira
     `IDataProtectionKeyContext` (vidi kako je urađeno u ovom fajlu);
   - `Views/Shared/_LoginPartial.cshtml`, `Views/Home/StatusCode.cshtml` + akcija `HttpStatusCode` iz `HomeController`-a;
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
   - **nijednu skriptu direktno u HTML-u bez nonce-a** (vidi 5.15), inače će je CSP blokirati.
5. **`_ViewImports.cshtml`** - dodaj `@using TvojaAplikacija.Security`.
6. **appsettings.json** - prenesi sekcije `SMTP` i `Security`.
7. **Migracija baze** - kao u opciji A, korak 4.
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

**Uloge (npr. administrator)** - sistem već ima podršku za uloge (`IdentityRole` u `Program.cs`), ali **nema stranicu za
dodeljivanje uloga**. Najjednostavnije je da se uloga napravi i dodeli pri pokretanju. Primer koji se dodaje u `Program.cs`
posle `var app = builder.Build();`:

```csharp
using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var userManager = scope.ServiceProvider.GetRequiredService<UserManager<IdentityUser>>();

    if (!await roleManager.RoleExistsAsync("Admin"))
        await roleManager.CreateAsync(new IdentityRole("Admin"));

    var admin = await userManager.FindByEmailAsync("admin@tvojafirma.rs");   // mora prvo da se registruje
    if (admin != null && !await userManager.IsInRoleAsync(admin, "Admin"))
        await userManager.AddToRoleAsync(admin, "Admin");
}
```

Zatim zaštiti stranicu:

```csharp
[Authorize(Roles = "Admin")]
public class AdminController : Controller { ... }
```

U view-u možeš prikazati nešto samo administratoru: `@if (User.IsInRole("Admin")) { ... }`.

> Posle dodele uloge korisnik treba da se odjavi i ponovo prijavi (ili sačeka do 5 minuta) da bi uloga postala aktivna.

**Osetljive radnje u tvojoj aplikaciji** (npr. isplata, brisanje) - dodaj i `[RequireRecentAuthentication]` da se lozinka
traži ponovo (vidi 5.10).

---

## 9. Sva podešavanja na jednom mestu

`appsettings.json` (tajne vrednosti stavljaj u `appsettings.Local.json` ili user-secrets, **nikad u git**):

| Podešavanje | Značenje | Podrazumevano |
|-------------|----------|---------------|
| `ConnectionStrings:Default` | Adresa baze | - |
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

---

## 10. Pre puštanja u rad (produkcija)

- [ ] Sajt radi isključivo preko **HTTPS-a** (sertifikat, npr. Let's Encrypt).
- [ ] Okruženje je **Production** (`ASPNETCORE_ENVIRONMENT=Production`) - tada se ne prikazuje link za potvrdu na ekranu i uključuje se HSTS.
- [ ] Lozinke i ključevi su u **tajnim podešavanjima** servera (environment variables, Azure Key Vault...), ne u `appsettings.json`.
  Primer imena promenljive: `SMTP__Password`, `ConnectionStrings__Default` (dve donje crte umesto dvotačke).
- [ ] **SMTP radi** - pošalji sebi test (registracija ili "Forgot password").
- [ ] Migracija je primenjena na produkcionu bazu (`dotnet ef database update` ili SQL skripta: `dotnet ef migrations script`).
- [ ] Ako postoji reverse proxy - upisan je u `Security:KnownProxies`.
- [ ] Ako se koriste passkey-ovi na više poddomena - podešen `Security:PasskeyServerDomain`.
- [ ] Google/Facebook: u njihovim konzolama upisana je adresa povratka `https://tvojsajt/signin-google` odnosno `/signin-facebook`.
- [ ] Logovi se čuvaju i prate (audit log - traži `Security audit:`).
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
8. Prijavi se na drugom browseru → na prvom "Sign out everywhere" → za najviše 5 minuta drugi browser je odjavljen.
9. Manage → Personal data: preuzmi JSON; napravi probni nalog i obriši ga.
10. Otvori nepostojeću adresu (npr. `/nesto`) → lepa stranica 404.
11. Uključi tamnu temu (ikonica meseca gore desno) → izgled se menja i pamti.

Ako sve prolazi - sistem je spreman, a ti možeš da se posvetiš stvarnoj funkcionalnosti svoje aplikacije.
