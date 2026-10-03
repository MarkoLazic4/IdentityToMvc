# Add: Unlock link

`dotnet new identitymvc-add --feature unlock-link` copied the files that belong to this feature.
Finish by adding the code below to the shared files of your project (in the same order).

A block marked "only if ..." applies only when your app also has that feature.
Tip: the same file in a new app made with `dotnet new identitymvc --tier full` shows the finished code.

## 1. Add to `IdentityToMvc.Tests/AccountSecurityTests.cs`

Only if your app has the test project.

Put it below this line (in the same block): `Assert.Contains("/Lockout", locked.Headers.Location!.OriginalString);`

```csharp

        // The owner gets a link that lifts the lock
        var unlockEmail = await _factory.Mailbox.WaitForAsync(email, received, e => e.Subject == _factory.Text("Your account was locked"));
        using var owner = _factory.CreateBrowser();
        await owner.GetAsync(unlockEmail.Link("/Unlock"));

        var login = await owner.LoginAsync(email);
        Assert.Equal(HttpStatusCode.Redirect, login.StatusCode);
        Assert.DoesNotContain("/Lockout", login.Headers.Location!.OriginalString);
```

## 2. Add to `IdentityToMvc.Web/Areas/User/Controllers/AccountController.cs`

Put it below this line (in the same block): `await _securityNotifier.NotifyAsync(user, SecurityEvent.AccountLockedOut, sendEmail: false);`

```csharp
                // Give the owner a way out: an attacker who keeps locking the account can't keep them out
                var code = await _userManager.GenerateUserTokenAsync(user, TokenOptions.DefaultProvider, UnlockTokenPurpose);
                var callbackUrl = Url.Action(nameof(Unlock), "Account",
                    new { area = "User", userId = user.Id, code = TokenEncoder.Encode(code) }, Request.Scheme) ?? string.Empty;
                _emailQueue.Enqueue(email, _templates.UnlockAccountSubject, _templates.UnlockAccount(callbackUrl));
```

## 3. Add to `IdentityToMvc.Web/Areas/User/Views/Account/Lockout.cshtml`

Put it below this line (in the same block): `var hint = L["Too many failed attempts. For your security this account has been locked - please try again in a few minutes."];`

```cshtml
    hint = L["Too many failed attempts. For your security this account has been locked - please try again in a few minutes or use the unlock link we emailed you."];
```

## 4. Add to `IdentityToMvc.Web/Areas/User/Views/Account/Lockout.cshtml`

Only if your app has passkeys.

Put it below this line (in the same block): `var hint = L["Too many failed attempts. For your security this account has been locked - please try again in a few minutes."];`

```cshtml
    hint = L["Too many failed attempts. For your security this account has been locked - please try again in a few minutes, use a passkey, or use the unlock link we emailed you."];
```

## 5. Add to `IdentityToMvc.Web/Services/EmailTemplates.cs`

Put it below this line (in the same block): `_t["Choose password"], callbackUrl);`

```csharp
        public string UnlockAccountSubject => _t["Your account was locked"];
        public string UnlockAccount(string callbackUrl) =>
            Build(_t["Unlock your account"],
                _t["Your account was locked after several failed login attempts. If that was you, you can unlock it right away. If it wasn't, someone may be guessing your password - consider changing it."],
                _t["Unlock account"], callbackUrl);
```
