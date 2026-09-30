# Add: Personal data (GDPR)

`dotnet new identitymvc-add --feature personal-data` copied the files that belong to this feature.
Finish by adding the code below to the shared files of your project (in the same order).

A block marked "only if ..." applies only when your app also has that feature.
Tip: the same file in a new app made with `dotnet new identitymvc --tier full` shows the finished code.

## 1. Add to `IdentityToMvc.Web/Areas/User/Views/Manage/_ManageNav.cshtml`

Put it below this line (in the same block): `<i class="bi bi-key"></i> @L["Password"]`

```cshtml
        <li class="nav-item">
            <a asp-area="User" asp-controller="Manage" asp-action="PersonalData" class="nav-link @NavActive("PersonalData", "DeletePersonalData")" id="personal-data">
                <i class="bi bi-file-earmark-person"></i> @L["Personal data"]
            </a>
        </li>
```
