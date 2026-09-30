# Add: Two-factor authentication

`dotnet new identitymvc-add --feature two-factor` copied the files that belong to this feature.
Finish by adding the code below to the shared files of your project (in the same order).

A block marked "only if ..." applies only when your app also has that feature.
Tip: the same file in a new app made with `dotnet new identitymvc --tier full` shows the finished code.

## 1. Add to `IdentityToMvc.Web/Areas/Admin/Controllers/UsersController.cs`

Only if your app has the admin panel.

Put it just above this line: `// POST: /Admin/Users/ConfirmEmail/{id}`

```csharp
        // POST: /Admin/Users/ResetTwoFactor/{id}
        [HttpPost]
        [ValidateAntiForgeryToken]
        [RequireRecentAuthentication]
        public Task<IActionResult> ResetTwoFactor(string id) => ChangeUserAsync(id, protectSelf: true, async (user, admin) =>
        {
            await _userManager.SetTwoFactorEnabledAsync(user, false);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 0);
            await SignOutEverywhereAsync(user);
            await _notifier.NotifyAsync(user, SecurityEvent.AdminResetTwoFactor, actor: admin);
            return _t["Two-factor authentication was turned off and the authenticator key was reset."];
        });
```

## 2. Add to `IdentityToMvc.Web/Areas/Admin/Views/Dashboard/Index.cshtml`

Only if your app has the admin panel.

Put it below this line (in the same block): `<div class="stat-note">@L["{0}% confirmed their email", Model.Percent(Model.ConfirmedUsers)]</div>`

```cshtml
    <div class="stat">
        <div class="stat-label">@L["Two-factor"]</div>
        <div class="stat-value">@Model.Percent(Model.TwoFactorUsers)%</div>
        <div class="stat-note">@L["{0} users", Model.TwoFactorUsers]</div>
    </div>
```

## 3. Add to `IdentityToMvc.Web/Areas/Admin/Views/Users/Details.cshtml`

Only if your app has the admin panel.

Put it below this line (in the same block): `<div><span>@L["Password"]</span><strong>@(Model.HasPassword ? L["Yes"] : L["No"])</strong></div>`

```cshtml
    <div><span>@L["Two-factor"]</span><strong>@(Model.TwoFactorEnabled ? L["On"] : L["Off"])</strong></div>
```

## 4. Add to `IdentityToMvc.Web/Areas/Admin/Views/Users/Details.cshtml`

Only if your app has the admin panel.

Put it below this line (in the same block): `<button type="submit" class="btn btn-soft" id="signout-user">@L["Sign out everywhere"]</button>`

```cshtml
        @if (Model.TwoFactorEnabled)
        {
            <form asp-area="Admin" asp-controller="Users" asp-action="ResetTwoFactor" asp-route-id="@Model.Id" method="post" data-confirm="@L["Turn off two-factor authentication for this user?"]">
                <button type="submit" class="btn btn-outline-danger">@L["Reset 2FA"]</button>
            </form>
        }
```

## 5. Add to `IdentityToMvc.Web/Areas/Admin/Views/Users/Index.cshtml`

Only if your app has the admin panel.

Put it below this line (in the same block): `<span class="badge text-bg-warning">@L["Unconfirmed"]</span>`

```cshtml
                            @if (user.TwoFactorEnabled)
                            {
                                <span class="badge text-bg-success">2FA</span>
                            }
```

## 6. Add to `IdentityToMvc.Web/Areas/User/Controllers/AccountController.ExternalLogins.cs`

Only if your app has Google or Facebook login.

Put it just above this line: `if (result.IsLockedOut)`

```csharp
            if (result.RequiresTwoFactor)
            {
                return RedirectToAction(nameof(LoginWith2fa), "Account", new { area = "User", returnUrl, rememberMe = false });
            }
```

## 7. Add to `IdentityToMvc.Web/Areas/User/Controllers/AccountController.cs`

Put it just above this line: `if (result.IsLockedOut)`

```csharp
                if (result.RequiresTwoFactor)
                {
                    return RedirectToAction(nameof(LoginWith2fa), "Account", new { area = "User", returnUrl = model.ReturnUrl, rememberMe = model.Input.RememberMe });
                }
```

## 8. Add to `IdentityToMvc.Web/Areas/User/Views/Manage/_ManageNav.cshtml`

Put it below this line (in the same block): `<i class="bi bi-key"></i> @L["Password"]`

```cshtml
        @if (options.EnableTwoFactor)
        {
            <li class="nav-item">
                <a asp-area="User" asp-controller="Manage" asp-action="TwoFactorAuthentication" class="nav-link @NavActive("TwoFactorAuthentication", "EnableAuthenticator", "Disable2fa", "ResetAuthenticator", "GenerateRecoveryCodes", "ShowRecoveryCodes")" id="two-factor">
                    <i class="bi bi-shield-lock"></i> @L["Two-factor authentication"]
                </a>
            </li>
        }
```

## 9. Add to `IdentityToMvc.Web/Program.cs`

Put it below this line (in the same block): `.AddPasswordValidator<UserInfoPasswordValidator>();`

```csharp
// Encrypts the authenticator key and hashes recovery codes (see ProtectedUserStore)
identity.AddUserStore<ProtectedUserStore>();
```

## 10. Add to `IdentityToMvc.Web/Security/RequireAdminSecurityAttribute.cs`

Only if your app has the admin panel.

Put it just above this line: `var required = _configuration.GetValue("Security:RequireTwoFactorForAdmins", true) && available;`

```csharp
                if (options.EnableTwoFactor)
                {
                    available = true;
                    setupPage = "TwoFactorAuthentication";
                }
```

## 11. Add to `IdentityToMvc.Web/Security/SecurityOptions.cs`

Put it at the top of the { } block that follows this line: `public sealed class SecurityOptions`

```csharp
        /// <summary>Two-factor authentication (authenticator app + recovery codes) in Manage account.</summary>
        public bool EnableTwoFactor { get; set; } = true;
```

## 12. Add to `IdentityToMvc.Web/Security/SecurityOptions.cs`

Put it at the top of the { } block that follows this line: `public enum SecurityFeature`

```csharp
        TwoFactor,
```

## 13. Add to `IdentityToMvc.Web/Security/SecurityOptions.cs`

Put it just above this line: `_ => true`

```csharp
            SecurityFeature.TwoFactor => options.EnableTwoFactor,
```

## 14. Add to `IdentityToMvc.Web/Views/Home/Index.cshtml`

Put it below this line (in the same block): `<i class="bi bi-person-gear me-1"></i> @L["Manage your account"]`

```cshtml
            @if (SecurityOptions.CurrentValue.EnableTwoFactor)
            {
                <a class="btn btn-outline-primary btn-lg px-4" asp-area="User" asp-controller="Manage" asp-action="TwoFactorAuthentication">
                    <i class="bi bi-shield-check me-1"></i> @L["Security settings"]
                </a>
            }
```

## 15. Add to `IdentityToMvc.Web/Views/Home/Index.cshtml`

Put it below this line (in the same block): `<p>@L["Local and external logins, \"remember me\" and lockout after repeated failed attempts."]</p>`

```cshtml
    <div class="col-md-6 col-lg-4">
        <div class="card feature-card">
            <span class="icon-badge"><i class="bi bi-shield-lock"></i></span>
            <h3>@L["Two-factor authentication"]</h3>
            <p>@L["Authenticator apps with QR code setup, remembered browsers and one-time recovery codes."]</p>
        </div>
    </div>
```

## 16. Add to `IdentityToMvc.Web/Views/Shared/_LoginPartial.cshtml`

Put it below this line (in the same block): `<i class="bi bi-person-gear me-2"></i>@L["Manage account"]`

```cshtml
            @if (SecurityOptions.CurrentValue.EnableTwoFactor)
            {
                <li>
                    <a class="dropdown-item" asp-area="User" asp-controller="Manage" asp-action="TwoFactorAuthentication">
                        <i class="bi bi-shield-check me-2"></i>@L["Security"]
                    </a>
                </li>
            }
```

## 17. Add to `IdentityToMvc.Web/appsettings.json`

Put it below this line (in the same block): `"Security": {`

```json
    "EnableTwoFactor": true,
```
