# Add: Facebook login

`dotnet new identitymvc-add --feature facebook` copied the files that belong to this feature.
Finish by adding the code below to the shared files of your project (in the same order).

A block marked "only if ..." applies only when your app also has that feature.
Tip: the same file in a new app made with `dotnet new identitymvc --tier full` shows the finished code.

## 1. Add to `IdentityToMvc.Web/Areas/Admin/Views/Users/Details.cshtml`

Only if your app has the admin panel.

Skip this step if your app already has Google login - the code is already there.

Put it just above this line: `<div><span>@L["Failed attempts"]</span><strong>@Model.AccessFailedCount</strong></div>`

```cshtml
    <div><span>@L["External logins"]</span><strong>@(Model.ExternalLogins.Count == 0 ? "-" : string.Join(", ", Model.ExternalLogins))</strong></div>
```

## 2. Add to `IdentityToMvc.Web/Areas/User/Views/Account/Login.cshtml`

Skip this step if your app already has Google login - the code is already there.

Put it below this line (in the same block): `<button id="login-submit" type="submit" class="w-100 btn btn-lg btn-primary">@L["Log in"]</button>`

```cshtml
        <partial name="_ExternalLoginButtons" model="(Model.ExternalLogins, Model.ReturnUrl, false)" />
```

## 3. Add to `IdentityToMvc.Web/Areas/User/Views/Account/Register.cshtml`

Skip this step if your app already has Google login - the code is already there.

Put it below this line (in the same block): `</form>`

```cshtml
        <partial name="_ExternalLoginButtons" model="(Model.ExternalLogins, Model.ReturnUrl, true)" />
```

## 4. Add to `IdentityToMvc.Web/Areas/User/Views/Manage/_ManageNav.cshtml`

Skip this step if your app already has Google login - the code is already there.

Put it below this line (in the same block): `<i class="bi bi-key"></i> @L["Password"]`

```cshtml
        @if (hasExternalLogins)
        {
            <li id="external-logins" class="nav-item">
                <a asp-area="User" asp-controller="Manage" asp-action="ExternalLogins" id="external-login" class="nav-link @NavActive("ExternalLogins")">
                    <i class="bi bi-link-45deg"></i> @L["External logins"]
                </a>
            </li>
        }
```

## 5. Add to `IdentityToMvc.Web/IdentityToMvc.Web.csproj`

Put it below this line (in the same block): `<!-- Database provider -->`

```xml
  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.Authentication.Facebook" Version="10.0.12" />
  </ItemGroup>
```

## 6. Add to `IdentityToMvc.Web/Program.cs`

Put it below this line (in the same block): `// "Log in with ..." buttons never show up for a provider that can't work.`

```csharp
if (!string.IsNullOrWhiteSpace(builder.Configuration["FacebookAppId"]))
{
    builder.Services.AddAuthentication().AddFacebook(options =>
    {
        options.AppId = builder.Configuration["FacebookAppId"]!;
        options.AppSecret = builder.Configuration["FacebookAppSecret"]!;
    });
}
```

## 7. Add to `IdentityToMvc.Web/Security/SecurityHeadersMiddleware.cs`

Put it below this line (in the same block): `private const string ExternalLoginOrigins = ""`

```csharp
            + " https://www.facebook.com https://m.facebook.com"
```

## 8. Add to `IdentityToMvc.Web/appsettings.json`

Put it just above this line: `"Security": {`

```json
  "FacebookAppId": "",
  "FacebookAppSecret": "",
```
