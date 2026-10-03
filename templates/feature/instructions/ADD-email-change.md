# Add: Email change

`dotnet new identitymvc-add --feature email-change` copied the files that belong to this feature.
Finish by adding the code below to the shared files of your project (in the same order).

A block marked "only if ..." applies only when your app also has that feature.
Tip: the same file in a new app made with `dotnet new identitymvc --tier full` shows the finished code.

## 1. Add to `IdentityToMvc.Web/Areas/User/Views/Manage/_ManageNav.cshtml`

Put it below this line (in the same block): `<ul class="nav nav-pills flex-column gap-1">`

```cshtml
        <li class="nav-item">
            <a asp-area="User" asp-controller="Manage" asp-action="Email" class="nav-link @NavActive("Email", "ChangeEmail", "SendVerificationEmail")" id="email">
                <i class="bi bi-envelope"></i> @L["Email"]
            </a>
        </li>
```

## 2. Add to `IdentityToMvc.Web/Services/EmailTemplates.cs`

Put it just above this line: `public string ResetPasswordSubject => _t["Reset your password"];`

```csharp
        public string ConfirmEmailChangeSubject => _t["Confirm your new email"];
        public string ConfirmEmailChange(string callbackUrl) =>
            Build(_t["Confirm your new email"],
                _t["You asked to change the email address on your account. Confirm the new address to finish the change."],
                _t["Confirm new email"], callbackUrl);
```
