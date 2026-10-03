# Add: Breached password check

`dotnet new identitymvc-add --feature breached-passwords` copied the files that belong to this feature.
Finish by adding the code below to the shared files of your project (in the same order).

A block marked "only if ..." applies only when your app also has that feature.
Tip: the same file in a new app made with `dotnet new identitymvc --tier full` shows the finished code.

## 1. Add to `IdentityToMvc.Web/Program.cs`

Put it below this line (in the same block): `.AddPasswordValidator<UserInfoPasswordValidator>();`

```csharp
identity.AddPasswordValidator<BreachedPasswordValidator>();
```

## 2. Add to `IdentityToMvc.Web/Program.cs`

Put it just above this line: `builder.Services.AddAccountRateLimiting();`

```csharp
builder.Services.AddHttpClient(BreachedPasswordValidator.HttpClientName, client =>
{
    client.BaseAddress = new Uri("https://api.pwnedpasswords.com/");
    client.Timeout = TimeSpan.FromSeconds(3);
    client.DefaultRequestHeaders.UserAgent.ParseAdd("IdentityToMvc-PasswordCheck");
});
```

## 3. Add to `IdentityToMvc.Web/Security/SecurityOptions.cs`

Put it below this line (in the same block): `public bool EnableRateLimiting { get; set; } = true;`

```csharp
        /// <summary>Check new passwords against the Have I Been Pwned breach corpus.</summary>
        public bool CheckBreachedPasswords { get; set; } = true;
```

## 4. Add to `IdentityToMvc.Web/appsettings.json`

Put it below this line (in the same block): `"EnableRateLimiting": true,`

```json
    "CheckBreachedPasswords": true,
```
