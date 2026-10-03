# Add: Devices page

`dotnet new identitymvc-add --feature devices` copied the files that belong to this feature.
Finish by adding the code below to the shared files of your project (in the same order).

A block marked "only if ..." applies only when your app also has that feature.
Tip: the same file in a new app made with `dotnet new identitymvc --tier full` shows the finished code.

## 1. Add to `IdentityToMvc.Tests/AccountSecurityTests.cs`

Only if your app has the test project.

Put it below this line (in the same block): `Assert.Contains("LoginFailed", events);`

```csharp
    [Fact]
    public async Task Signing_out_everywhere_ends_the_other_sessions()
    {
        var email = NewEmail();
        using var laptop = _factory.CreateBrowser();
        await laptop.CreateConfirmedUserAndLoginAsync(email);

        using var phone = _factory.CreateBrowser();
        Assert.Equal(HttpStatusCode.Redirect, (await phone.LoginAsync(email)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await phone.GetAsync("/User/Account/Manage/ChangePassword")).StatusCode);

        var devices = await laptop.GetPageAsync("/User/Account/Manage/Devices");
        var result = await laptop.PostAsync("/User/Account/Manage/SignOutEverywhere", new Dictionary<string, string>(),
            TestBrowser.AntiforgeryToken(devices));
        Assert.Equal(HttpStatusCode.Redirect, result.StatusCode);

        // The phone is sent back to the login page, the laptop stays signed in
        var phoneAfter = await phone.GetAsync("/User/Account/Manage/ChangePassword");
        Assert.Equal(HttpStatusCode.Redirect, phoneAfter.StatusCode);
        Assert.Contains("/User/Account/Login", phoneAfter.Headers.Location!.OriginalString);
        Assert.Equal(HttpStatusCode.OK, (await laptop.GetAsync("/User/Account/Manage/ChangePassword")).StatusCode);
    }
```

## 2. Add to `IdentityToMvc.Web/Areas/User/Views/Manage/_ManageNav.cshtml`

Put it below this line (in the same block): `<i class="bi bi-key"></i> @L["Password"]`

```cshtml
        <li class="nav-item">
            <a asp-area="User" asp-controller="Manage" asp-action="Devices" class="nav-link @NavActive("Devices", "RevokeSession")" id="devices">
                <i class="bi bi-laptop"></i> @L["Devices"]
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
