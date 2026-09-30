using System.Text.Encodings.Web;

namespace IdentityToMvc.Web.Services
{
    /// <summary>
    /// Builds the HTML bodies for the transactional emails sent by the account flows.
    /// </summary>
    public static class EmailTemplates
    {
        public static string ConfirmAccount(string callbackUrl) =>
            Build("Confirm your email",
                "Thanks for signing up! Please confirm your email address to activate your account. If you didn't create an account, ignore this email and don't click the button.",
                "Confirm email", callbackUrl);

        public static string AccountAlreadyExists(string loginUrl, string resetUrl) =>
            Build("You already have an account",
                "Someone just tried to create an account with this email address, but you already have one. If it was you, log in or reset your password. If it wasn't you, you can ignore this email - nothing was changed.",
                "Log in", loginUrl, $"Forgot your password? {resetUrl}");

        public static string FinishSetup(string callbackUrl) =>
            Build("Finish setting up your account",
                "Choose a password to confirm your email address and activate your account. If you didn't create an account, you can ignore this email.",
                "Choose password", callbackUrl);

        public static string UnlockAccount(string callbackUrl) =>
            Build("Unlock your account",
                "Your account was locked after several failed login attempts. If that was you, you can unlock it right away. If it wasn't, someone may be guessing your password - consider changing it.",
                "Unlock account", callbackUrl);

        public static string ConfirmEmailChange(string callbackUrl) =>
            Build("Confirm your new email",
                "You asked to change the email address on your account. Confirm the new address to finish the change.",
                "Confirm new email", callbackUrl);

        public static string ResetPassword(string callbackUrl) =>
            Build("Reset your password",
                "We received a request to reset your password. If you didn't ask for this, you can ignore this email.",
                "Reset password", callbackUrl);

        public static string SecurityNotification(string title, string text, DateTimeOffset when, string ip, string userAgent)
        {
            var encoder = HtmlEncoder.Default;
            return $"""
                <div style="font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#f4f5fb;padding:32px 16px;">
                  <div style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:12px;padding:32px;">
                    <h1 style="margin:0 0 16px;font-size:22px;color:#1f2340;">{encoder.Encode(title)}</h1>
                    <p style="margin:0 0 16px;font-size:15px;line-height:1.5;color:#4a4f6a;">{encoder.Encode(text)}</p>
                    <table style="font-size:13px;color:#4a4f6a;margin:0 0 20px;border-collapse:collapse;">
                      <tr><td style="padding:2px 12px 2px 0;color:#8a8fa8;">When</td><td>{encoder.Encode(when.ToString("yyyy-MM-dd HH:mm 'UTC'"))}</td></tr>
                      <tr><td style="padding:2px 12px 2px 0;color:#8a8fa8;">IP address</td><td>{encoder.Encode(ip)}</td></tr>
                      <tr><td style="padding:2px 12px 2px 0;color:#8a8fa8;">Device</td><td>{encoder.Encode(userAgent)}</td></tr>
                    </table>
                    <p style="margin:0;font-size:14px;line-height:1.5;color:#b91c1c;">If this wasn't you, reset your password immediately and review your two-factor authentication settings.</p>
                  </div>
                </div>
                """;
        }

        private static string Build(string title, string text, string buttonText, string url, string? extra = null)
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
                    <p style="margin:24px 0 0;font-size:12px;color:#8a8fa8;">If the button doesn't work, copy this link into your browser:<br><a href="{href}" style="color:#4f46e5;word-break:break-all;">{href}</a></p>
                  </div>
                </div>
                """;
        }
    }
}
