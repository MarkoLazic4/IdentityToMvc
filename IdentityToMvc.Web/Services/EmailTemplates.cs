using System.Text.Encodings.Web;
using Microsoft.Extensions.Localization;

namespace IdentityToMvc.Web.Services
{
    /// <summary>
    /// Builds the HTML bodies (and subjects) of the transactional emails, in the language of the
    /// current request.
    /// </summary>
    public sealed class EmailTemplates
    {
        private readonly IStringLocalizer<SharedResource> _t;

        public EmailTemplates(IStringLocalizer<SharedResource> localizer)
        {
            _t = localizer;
        }

        public string ConfirmAccountSubject => _t["Confirm your email"];
        public string ConfirmAccount(string callbackUrl) =>
            Build(_t["Confirm your email"],
                _t["Thanks for signing up! Please confirm your email address to activate your account. If you didn't create an account, ignore this email and don't click the button."],
                _t["Confirm email"], callbackUrl);

        public string AccountAlreadyExistsSubject => _t["You already have an account"];
        public string AccountAlreadyExists(string loginUrl, string resetUrl) =>
            Build(_t["You already have an account"],
                _t["Someone just tried to create an account with this email address, but you already have one. If it was you, log in or reset your password. If it wasn't you, you can ignore this email - nothing was changed."],
                _t["Log in"], loginUrl, _t["Forgot your password? {0}", resetUrl]);

        public string FinishSetupSubject => _t["Finish setting up your account"];
        public string FinishSetup(string callbackUrl) =>
            Build(_t["Finish setting up your account"],
                _t["Choose a password to confirm your email address and activate your account. If you didn't create an account, you can ignore this email."],
                _t["Choose password"], callbackUrl);

#if (UnlockLink)
        public string UnlockAccountSubject => _t["Your account was locked"];
        public string UnlockAccount(string callbackUrl) =>
            Build(_t["Unlock your account"],
                _t["Your account was locked after several failed login attempts. If that was you, you can unlock it right away. If it wasn't, someone may be guessing your password - consider changing it."],
                _t["Unlock account"], callbackUrl);
#endif

#if (EmailChange)
        public string ConfirmEmailChangeSubject => _t["Confirm your new email"];
        public string ConfirmEmailChange(string callbackUrl) =>
            Build(_t["Confirm your new email"],
                _t["You asked to change the email address on your account. Confirm the new address to finish the change."],
                _t["Confirm new email"], callbackUrl);
#endif

        public string ResetPasswordSubject => _t["Reset your password"];
        public string ResetPassword(string callbackUrl) =>
            Build(_t["Reset your password"],
                _t["We received a request to reset your password. If you didn't ask for this, you can ignore this email."],
                _t["Reset password"], callbackUrl);

#if (Notifications)
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
#endif

        private string Build(string title, string text, string buttonText, string url, string? extra = null)
        {
            var encoder = HtmlEncoder.Default;
            var href = encoder.Encode(url);
            var extraHtml = extra == null ? string.Empty
                : $"<p style=\"margin:16px 0 0;font-size:13px;color:#4a4f6a;word-break:break-all;\">{encoder.Encode(extra)}</p>";

            return $"""
                <div style="font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#f4f5fb;padding:32px 16px;">
                  <div style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:12px;padding:32px;">
                    <h1 style="margin:0 0 16px;font-size:22px;color:#1f2340;">{encoder.Encode(title)}</h1>
                    <p style="margin:0 0 24px;font-size:15px;line-height:1.5;color:#4a4f6a;">{encoder.Encode(text)}</p>
                    <a href="{href}" style="display:inline-block;background:#4f46e5;color:#ffffff;text-decoration:none;padding:12px 24px;border-radius:8px;font-weight:600;">{encoder.Encode(buttonText)}</a>
                    {extraHtml}
                    <p style="margin:24px 0 0;font-size:12px;color:#8a8fa8;">{encoder.Encode(_t["If the button doesn't work, copy this link into your browser:"])}<br><a href="{href}" style="color:#4f46e5;word-break:break-all;">{href}</a></p>
                  </div>
                </div>
                """;
        }
    }
}
