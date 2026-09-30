# Add: Admin panel

`dotnet new identitymvc-add --feature admin` copied the files that belong to this feature.
Finish by adding the code below to the shared files of your project (in the same order).

A block marked "only if ..." applies only when your app also has that feature.
Tip: the same file in a new app made with `dotnet new identitymvc --tier full` shows the finished code.

## 1. Add to `IdentityToMvc.Web/Areas/User/Controllers/AccountController.ExternalLogins.cs`

Only if your app has Google or Facebook login.

Put it below this line (in the same block): `_logger.LogInformation("User created an account using {Name} provider.", info.LoginProvider);`

```csharp
                    await _adminBootstrapper.EnsureAdminAsync(user);
```

## 2. Add to `IdentityToMvc.Web/Areas/User/Controllers/AccountController.cs`

Put it just above this line: `private readonly EmailTemplates _templates;`

```csharp
        private readonly AdminBootstrapper _adminBootstrapper;
```

## 3. Add to `IdentityToMvc.Web/Areas/User/Controllers/AccountController.cs`

Put it just above this line: `ILogger<AccountController> logger)`

```csharp
            AdminBootstrapper adminBootstrapper,
```

## 4. Add to `IdentityToMvc.Web/Areas/User/Controllers/AccountController.cs`

Put it just above this line: `_sessions = sessions;`

```csharp
            _adminBootstrapper = adminBootstrapper;
```

## 5. Add to `IdentityToMvc.Web/Areas/User/Controllers/AccountController.cs`

Put it just above this line: `this.StatusSuccess(_t["Thank you for confirming your email. You can now log in."]);`

```csharp
                await _adminBootstrapper.EnsureAdminAsync(user);
```

## 6. Add to `IdentityToMvc.Web/Areas/User/Controllers/AccountController.cs`

Put it below this line (in the same block): `await _userManager.ConfirmEmailAsync(user, confirmToken);`

```csharp
                    await _adminBootstrapper.EnsureAdminAsync(user);
```

## 7. Add to `IdentityToMvc.Web/Program.cs`

Put it just above this line: `builder.Services.AddHostedService<DataRetentionService>();`

```csharp
builder.Services.AddScoped<AdminBootstrapper>();
```

## 8. Add to `IdentityToMvc.Web/Program.cs`

Put it just above this line: `// Prepare the timing-equalizer hash in the background so even the first login is not measurably faster`

```csharp
// Create the Admin role and promote the accounts listed in "Admin:Emails"
using (var scope = app.Services.CreateScope())
{
    try
    {
        await scope.ServiceProvider.GetRequiredService<AdminBootstrapper>().InitializeAsync();
    }
    catch (Exception ex)
    {
        app.Logger.LogError(ex, "Could not initialize the Admin role. Has the database migration been applied?");
    }
}
```

## 9. Add to `IdentityToMvc.Web/Views/Home/Index.cshtml`

Put it below this line (in the same block): `<p>@L["Local and external logins, \"remember me\" and lockout after repeated failed attempts."]</p>`

```cshtml
    <div class="col-md-6 col-lg-4">
        <div class="card feature-card">
            <span class="icon-badge"><i class="bi bi-speedometer2"></i></span>
            <h3>@L["Admin panel"]</h3>
            <p>@L["Manage users and roles, lock accounts and follow every security event in the audit log."]</p>
        </div>
    </div>
```

## 10. Add to `IdentityToMvc.Web/Views/Shared/_LoginPartial.cshtml`

Put it just above this line: `<li><hr class="dropdown-divider"></li>`

```cshtml
            @if (User.IsInRole(AdminBootstrapper.AdminRole))
            {
                <li>
                    <a id="admin-panel" class="dropdown-item" asp-area="Admin" asp-controller="Dashboard" asp-action="Index">
                        <i class="bi bi-speedometer2 me-2"></i>@L["Admin panel"]
                    </a>
                </li>
            }
```

## 11. Add to `IdentityToMvc.Web/appsettings.json`

Only if your app has two-factor authentication or passkeys.

Put it just above this line: `"KnownProxies": [],`

```json
    "RequireTwoFactorForAdmins": true,
```

## 12. Add to `IdentityToMvc.Web/appsettings.json`

Put it just above this line: `"Localization": {`

```json
  "Admin": {
    "Emails": []
  },
```
