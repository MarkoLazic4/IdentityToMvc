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
                "Thanks for signing up! Please confirm your email address to activate your account.",
                "Confirm email", callbackUrl);

        public static string ConfirmEmailChange(string callbackUrl) =>
            Build("Confirm your new email",
                "You asked to change the email address on your account. Confirm the new address to finish the change.",
                "Confirm new email", callbackUrl);

        public static string ResetPassword(string callbackUrl) =>
            Build("Reset your password",
                "We received a request to reset your password. If you didn't ask for this, you can ignore this email.",
                "Reset password", callbackUrl);

        private static string Build(string title, string text, string buttonText, string url)
        {
            var encoder = HtmlEncoder.Default;
            var href = encoder.Encode(url);

            return $"""
                <div style="font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#f4f5fb;padding:32px 16px;">
                  <div style="max-width:480px;margin:0 auto;background:#ffffff;border-radius:12px;padding:32px;">
                    <h1 style="margin:0 0 16px;font-size:22px;color:#1f2340;">{encoder.Encode(title)}</h1>
                    <p style="margin:0 0 24px;font-size:15px;line-height:1.5;color:#4a4f6a;">{encoder.Encode(text)}</p>
                    <a href="{href}" style="display:inline-block;background:#4f46e5;color:#ffffff;text-decoration:none;padding:12px 24px;border-radius:8px;font-weight:600;">{encoder.Encode(buttonText)}</a>
                    <p style="margin:24px 0 0;font-size:12px;color:#8a8fa8;">If the button doesn't work, copy this link into your browser:<br><a href="{href}" style="color:#4f46e5;word-break:break-all;">{href}</a></p>
                  </div>
                </div>
                """;
        }
    }
}
