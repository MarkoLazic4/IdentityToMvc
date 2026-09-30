# Add: Passkeys

`dotnet new identitymvc-add --feature passkeys` copied the files that belong to this feature.
Finish by adding the code below to the shared files of your project (in the same order).

A block marked "only if ..." applies only when your app also has that feature.
Tip: the same file in a new app made with `dotnet new identitymvc --tier full` shows the finished code.

## 1. Add to `IdentityToMvc.Web/Areas/Admin/Views/Dashboard/Index.cshtml`

Only if your app has the admin panel.

Put it below this line (in the same block): `<div class="stat-note">@L["{0}% confirmed their email", Model.Percent(Model.ConfirmedUsers)]</div>`

```cshtml
    <div class="stat">
        <div class="stat-label">@L["Passkeys"]</div>
        <div class="stat-value">@Model.Percent(Model.PasskeyUsers)%</div>
        <div class="stat-note">@L["{0} users", Model.PasskeyUsers]</div>
    </div>
```

## 2. Add to `IdentityToMvc.Web/Areas/Admin/Views/Users/Details.cshtml`

Only if your app has the admin panel.

Put it below this line (in the same block): `<div><span>@L["Password"]</span><strong>@(Model.HasPassword ? L["Yes"] : L["No"])</strong></div>`

```cshtml
    <div><span>@L["Passkeys"]</span><strong>@Model.PasskeyCount</strong></div>
```

## 3. Add to `IdentityToMvc.Web/Areas/User/Views/Account/Lockout.cshtml`

Put it below this line (in the same block): `var hint = L["Too many failed attempts. For your security this account has been locked - please try again in a few minutes."];`

```cshtml
    hint = L["Too many failed attempts. For your security this account has been locked - please try again in a few minutes or use a passkey."];
```

## 4. Add to `IdentityToMvc.Web/Areas/User/Views/Account/Lockout.cshtml`

Only if your app has the unlock link.

Put it below this line (in the same block): `var hint = L["Too many failed attempts. For your security this account has been locked - please try again in a few minutes."];`

```cshtml
    hint = L["Too many failed attempts. For your security this account has been locked - please try again in a few minutes, use a passkey, or use the unlock link we emailed you."];
```

## 5. Add to `IdentityToMvc.Web/Areas/User/Views/Account/Login.cshtml`

Put it below this line (in the same block): `var passkeysEnabled = false;`

```cshtml
    passkeysEnabled = SecurityOptions.CurrentValue.EnablePasskeys;
```

## 6. Add to `IdentityToMvc.Web/Areas/User/Views/Account/Login.cshtml`

Put it below this line (in the same block): `<button id="login-submit" type="submit" class="w-100 btn btn-lg btn-primary">@L["Log in"]</button>`

```cshtml
        @if (passkeysEnabled)
        {
            <form id="passkey-login-form" asp-area="User" asp-controller="Account" asp-action="LoginWithPasskey" method="post"
                  data-options-url="@Url.Action("PasskeyRequestOptions", "Account", new { area = "User" })" data-passkey-supported>
                <input type="hidden" name="credentialJson" />
                <input type="hidden" name="returnUrl" value="@Model.ReturnUrl" />
                <button id="passkey-login-button" type="button" class="w-100 btn btn-lg btn-soft mt-2">
                    <i class="bi bi-fingerprint me-1"></i> @L["Log in with a passkey"]
                </button>
                <div id="passkey-login-error" class="text-danger small mt-2" role="alert" hidden></div>
            </form>
        }
```

## 7. Add to `IdentityToMvc.Web/Areas/User/Views/Account/Login.cshtml`

Put it below this line (in the same block): `<partial name="_ValidationScriptsPartial" />`

```cshtml
    @if (passkeysEnabled)
    {
        <script src="~/js/passkeys.js" asp-append-version="true"></script>
    }
```

## 8. Add to `IdentityToMvc.Web/Areas/User/Views/Manage/_ManageNav.cshtml`

Put it below this line (in the same block): `<i class="bi bi-key"></i> @L["Password"]`

```cshtml
        @if (options.EnablePasskeys)
        {
            <li class="nav-item">
                <a asp-area="User" asp-controller="Manage" asp-action="Passkeys" class="nav-link @NavActive("Passkeys", "AddPasskey", "RemovePasskey")" id="passkeys">
                    <i class="bi bi-fingerprint"></i> @L["Passkeys"]
                </a>
            </li>
        }
```

## 9. Add to `IdentityToMvc.Web/Program.cs`

Put it just above this line: `// OWASP 2023 recommendation for PBKDF2-HMAC-SHA512 is 210,000 iterations; PBKDF2-HMAC-SHA256`

```csharp
// Passkeys: require user verification (biometrics / device PIN) so a passkey is a real
// second factor on its own and can replace password + 2FA.
builder.Services.Configure<IdentityPasskeyOptions>(options =>
{
    options.UserVerificationRequirement = "required";
    options.ResidentKeyRequirement = "required";
    options.AuthenticatorTimeout = TimeSpan.FromMinutes(3);
    var serverDomain = builder.Configuration["Security:PasskeyServerDomain"];
    if (!string.IsNullOrWhiteSpace(serverDomain))
    {
        options.ServerDomain = serverDomain;
    }
});
```

## 10. Add to `IdentityToMvc.Web/Security/RequireAdminSecurityAttribute.cs`

Only if your app has the admin panel.

Put it below this line (in the same block): `var setupPage = "";`

```csharp
                if (options.EnablePasskeys)
                {
                    available = true;
                    setupPage = "Passkeys";
                }
```

## 11. Add to `IdentityToMvc.Web/Security/SecurityOptions.cs`

Put it just above this line: `/// <summary>"Sudo mode": ask for the password again before sensitive changes.</summary>`

```csharp
        /// <summary>Passkey (WebAuthn) login and the Manage account > Passkeys page.</summary>
        public bool EnablePasskeys { get; set; } = true;
```

## 12. Add to `IdentityToMvc.Web/Security/SecurityOptions.cs`

Put it below this line (in the same block): `public bool EnableRateLimiting { get; set; } = true;`

```csharp
        /// <summary>Maximum number of passkeys a user can register.</summary>
        public int MaxPasskeysPerUser { get; set; } = 10;
```

## 13. Add to `IdentityToMvc.Web/Security/SecurityOptions.cs`

Put it at the top of the { } block that follows this line: `public enum SecurityFeature`

```csharp
        Passkeys,
```

## 14. Add to `IdentityToMvc.Web/Security/SecurityOptions.cs`

Put it just above this line: `_ => true`

```csharp
            SecurityFeature.Passkeys => options.EnablePasskeys,
```

## 15. Add to `IdentityToMvc.Web/Views/Home/Index.cshtml`

Put it below this line (in the same block): `<p>@L["Local and external logins, \"remember me\" and lockout after repeated failed attempts."]</p>`

```cshtml
    <div class="col-md-6 col-lg-4">
        <div class="card feature-card">
            <span class="icon-badge"><i class="bi bi-fingerprint"></i></span>
            <h3>@L["Passkeys"]</h3>
            <p>@L["Passwordless, phishing-resistant login with a fingerprint, face or device PIN."]</p>
        </div>
    </div>
```

## 16. Add to `IdentityToMvc.Web/Views/Shared/_Layout.cshtml`

Put it below this line (in the same block): `["copied"] = L["Copied"].Value,`

```cshtml
        ["passkeyCancelled"] = L["The passkey request was cancelled or timed out."].Value,
        ["passkeyExists"] = L["This device already has a passkey for your account."].Value,
        ["passkeyFailed"] = L["Something went wrong with the passkey request."].Value,
        ["passkeyStart"] = L["Could not start the passkey request."].Value,
```

## 17. Add to `IdentityToMvc.Web/appsettings.json`

Put it just above this line: `"EnableRateLimiting": true,`

```json
    "EnablePasskeys": true,
    "MaxPasskeysPerUser": 10,
    "PasskeyServerDomain": "",
```
