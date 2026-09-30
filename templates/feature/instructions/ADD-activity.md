# Add: Security activity page

`dotnet new identitymvc-add --feature activity` copied the files that belong to this feature.
Finish by adding the code below to the shared files of your project (in the same order).

A block marked "only if ..." applies only when your app also has that feature.
Tip: the same file in a new app made with `dotnet new identitymvc --tier full` shows the finished code.

## 1. Add to `IdentityToMvc.Tests/AccountSecurityTests.cs`

Only if your app has the test project.

Put it below this line (in the same block): `Assert.Contains("LoginFailed", events);`

```csharp

        var activity = await browser.GetPageAsync("/User/Account/Manage/Activity");
        Assert.Contains(_factory.Text("Failed login attempt"), activity);
```

## 2. Add to `IdentityToMvc.Web/Areas/User/Views/Manage/_ManageNav.cshtml`

Put it below this line (in the same block): `<i class="bi bi-key"></i> @L["Password"]`

```cshtml
        <li class="nav-item">
            <a asp-area="User" asp-controller="Manage" asp-action="Activity" class="nav-link @NavActive("Activity")" id="activity">
                <i class="bi bi-clock-history"></i> @L["Security activity"]
            </a>
        </li>
```

## 3. Add to `IdentityToMvc.Web/Views/Home/Index.cshtml`

Put it below this line (in the same block): `<p>@L["Local and external logins, \"remember me\" and lockout after repeated failed attempts."]</p>`

```cshtml
    <div class="col-md-6 col-lg-4">
        <div class="card feature-card">
            <span class="icon-badge"><i class="bi bi-laptop"></i></span>
            <h3>@L["Devices & activity"]</h3>
            <p>@L["See where you're signed in, sign out a single device and review your security history."]</p>
        </div>
    </div>
```
