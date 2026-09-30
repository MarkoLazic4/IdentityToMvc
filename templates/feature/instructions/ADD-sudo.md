# Add: Sudo mode

`dotnet new identitymvc-add --feature sudo` copied the files that belong to this feature.
Finish by adding the code below to the shared files of your project (in the same order).

A block marked "only if ..." applies only when your app also has that feature.
Tip: the same file in a new app made with `dotnet new identitymvc --tier full` shows the finished code.

## 1. Add to `IdentityToMvc.Web/Program.cs`

Put it just above this line: `// Device sessions: a real sign-in starts a new session, a refresh keeps the current one`

```csharp
        services.GetRequiredService<RecentAuthenticationService>().OnSigningIn(context.HttpContext, context.Principal);
```

## 2. Add to `IdentityToMvc.Web/Security/RecentAuthentication.cs`

Put it just above this line: `public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)`

```csharp
            /// <summary>Sends the user to "Confirm it's you" when the last authentication is too old.</summary>
            private async Task<bool> RedirectToConfirmIdentityAsync(ActionExecutingContext context)
            {
                var httpContext = context.HttpContext;
                var options = httpContext.RequestServices.GetRequiredService<Microsoft.Extensions.Options.IOptionsMonitor<SecurityOptions>>().CurrentValue;
                var user = await _userManager.GetUserAsync(httpContext.User);
                if (!options.RequireRecentAuthentication
                    || user == null
                    || !await _userManager.HasPasswordAsync(user)
                    || await _recentAuthentication.IsRecentAsync(httpContext, user))
                {
                    return false;
                }

                // Come back to the page after confirming. For POSTs go back to the page the form was on.
                string? returnUrl = HttpMethods.IsGet(httpContext.Request.Method)
                    ? httpContext.Request.Path + httpContext.Request.QueryString
                    : LocalReferer(httpContext);

                context.Result = new RedirectToActionResult("ConfirmIdentity", "Manage", new { area = "User", returnUrl });
                return true;
            }

            private static string? LocalReferer(HttpContext context)
            {
                var referer = context.Request.Headers.Referer.ToString();
                if (Uri.TryCreate(referer, UriKind.Absolute, out var uri)
                    && string.Equals(uri.Host, context.Request.Host.Host, StringComparison.OrdinalIgnoreCase))
                {
                    return uri.PathAndQuery;
                }
                return null;
            }

```

## 3. Add to `IdentityToMvc.Web/Security/RecentAuthentication.cs`

Put it just above this line: `await next();`

```csharp
                if (await RedirectToConfirmIdentityAsync(context))
                {
                    return;
                }
```

## 4. Add to `IdentityToMvc.Web/appsettings.json`

Put it just above this line: `"EnableRateLimiting": true,`

```json
    "RequireRecentAuthentication": true,
```
