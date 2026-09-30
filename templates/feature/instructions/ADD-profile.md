# Add: Profile page

`dotnet new identitymvc-add --feature profile` copied the files that belong to this feature.
Finish by adding the code below to the shared files of your project (in the same order).

A block marked "only if ..." applies only when your app also has that feature.
Tip: the same file in a new app made with `dotnet new identitymvc --tier full` shows the finished code.

## 1. Add to `IdentityToMvc.Web/Areas/Admin/Views/Users/Details.cshtml`

Only if your app has the admin panel.

Put it just above this line: `<div><span>@L["Failed attempts"]</span><strong>@Model.AccessFailedCount</strong></div>`

```cshtml
    <div><span>@L["Phone number"]</span><strong>@(Model.PhoneNumber ?? "-")</strong></div>
```

## 2. Remove this code from `IdentityToMvc.Web/Areas/User/Controllers/ManageController.cs`

```csharp
        // ===========================================================================
        // GET: /User/Account/Manage/Index  (without the profile page, "Manage account" opens Password)
        // ===========================================================================
        [HttpGet]
        public IActionResult Index() => RedirectToAction(nameof(ChangePassword));

```

## 3. Add to `IdentityToMvc.Web/Areas/User/Views/Manage/_ManageNav.cshtml`

Put it below this line (in the same block): `<ul class="nav nav-pills flex-column gap-1">`

```cshtml
        <li class="nav-item">
            <a asp-area="User" asp-controller="Manage" asp-action="Index" class="nav-link @NavActive("Index")" id="profile">
                <i class="bi bi-person"></i> @L["Profile"]
            </a>
        </li>
```
