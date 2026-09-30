# Add: Security emails

`dotnet new identitymvc-add --feature notifications` copied the files that belong to this feature.
Finish by adding the code below to the shared files of your project (in the same order).

A block marked "only if ..." applies only when your app also has that feature.
Tip: the same file in a new app made with `dotnet new identitymvc --tier full` shows the finished code.

## 1. Add to `IdentityToMvc.Web/Security/SecurityNotifier.cs`

Put it below this line (in the same block): `await _db.SaveChangesAsync();`

```csharp
            var to = overrideEmail ?? user.Email;
            if (!sendEmail || AuditOnly.Contains(securityEvent)
                || !_options.CurrentValue.SendSecurityNotifications || string.IsNullOrEmpty(to))
            {
                return;
            }

            var title = SecurityEventText.Title(securityEvent, _t);
            var text = SecurityEventText.Description(securityEvent, _t);
            _emailQueue.Enqueue(to, title, _templates.SecurityNotification(title, text, now, ip, device));
```

## 2. Add to `IdentityToMvc.Web/Security/SecurityOptions.cs`

Put it below this line (in the same block): `public bool EnableRateLimiting { get; set; } = true;`

```csharp
        /// <summary>Send an email to the user when security-relevant changes happen on their account.</summary>
        public bool SendSecurityNotifications { get; set; } = true;
```

## 3. Add to `IdentityToMvc.Web/Services/EmailTemplates.cs`

Put it just above this line: `private string Build(string title, string text, string buttonText, string url, string? extra = null)`

```csharp
        public string SecurityNotification(string title, string text, DateTime whenUtc, string ip, string device)
        {
            var encoder = HtmlEncoder.Default;
            return $"""
                <div style="font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#f4f5fb;padding:32px 16px;">
                  <div style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:12px;padding:32px;">
                    <h1 style="margin:0 0 16px;font-size:22px;color:#1f2340;">{encoder.Encode(title)}</h1>
                    <p style="margin:0 0 16px;font-size:15px;line-height:1.5;color:#4a4f6a;">{encoder.Encode(text)}</p>
                    <table style="font-size:13px;color:#4a4f6a;margin:0 0 20px;border-collapse:collapse;">
                      <tr><td style="padding:2px 12px 2px 0;color:#8a8fa8;">{encoder.Encode(_t["When"])}</td><td>{encoder.Encode(whenUtc.ToString("yyyy-MM-dd HH:mm") + " UTC")}</td></tr>
                      <tr><td style="padding:2px 12px 2px 0;color:#8a8fa8;">{encoder.Encode(_t["IP address"])}</td><td>{encoder.Encode(ip)}</td></tr>
                      <tr><td style="padding:2px 12px 2px 0;color:#8a8fa8;">{encoder.Encode(_t["Device"])}</td><td>{encoder.Encode(device)}</td></tr>
                    </table>
                    <p style="margin:0;font-size:14px;line-height:1.5;color:#b91c1c;">{encoder.Encode(_t["If this wasn't you, reset your password immediately and review your two-factor authentication settings."])}</p>
                  </div>
                </div>
                """;
        }
```

## 4. Add to `IdentityToMvc.Web/appsettings.json`

Put it just above this line: `"KnownProxies": [],`

```json
    "SendSecurityNotifications": true,
```
