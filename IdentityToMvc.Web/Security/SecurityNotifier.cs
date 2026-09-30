using IdentityToMvc.Web.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;

namespace IdentityToMvc.Web.Security
{
    public enum SecurityEvent
    {
        PasswordChanged,
        PasswordReset,
        PasswordSet,
        EmailChangeRequested,
        EmailChanged,
        TwoFactorEnabled,
        TwoFactorDisabled,
        AuthenticatorReset,
        RecoveryCodesGenerated,
        ExternalLoginAdded,
        ExternalLoginRemoved,
        PasskeyAdded,
        PasskeyRemoved,
        SignedOutEverywhere,
        AccountLockedOut,
        AccountDeleted
    }

    /// <summary>
    /// Writes a structured audit log entry for security-relevant account changes and emails the
    /// account owner, so a hijacked account is noticed quickly ("wasn't you? reset your password").
    /// </summary>
    public interface ISecurityNotifier
    {
        /// <param name="overrideEmail">Send the notification to this address instead of the user's
        /// current one (e.g. the old address after an email change).</param>
        Task NotifyAsync(IdentityUser user, SecurityEvent securityEvent, string? overrideEmail = null);
    }

    public sealed class SecurityNotifier : ISecurityNotifier
    {
        private readonly IEmailQueue _emailQueue;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IOptionsMonitor<SecurityOptions> _options;
        private readonly ILogger<SecurityNotifier> _logger;

        public SecurityNotifier(IEmailQueue emailQueue, IHttpContextAccessor httpContextAccessor,
            IOptionsMonitor<SecurityOptions> options, ILogger<SecurityNotifier> logger)
        {
            _emailQueue = emailQueue;
            _httpContextAccessor = httpContextAccessor;
            _options = options;
            _logger = logger;
        }

        public Task NotifyAsync(IdentityUser user, SecurityEvent securityEvent, string? overrideEmail = null)
        {
            var httpContext = _httpContextAccessor.HttpContext;
            var ip = httpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var userAgent = httpContext?.Request.Headers.UserAgent.ToString() ?? string.Empty;
            if (userAgent.Length > 200)
                userAgent = userAgent[..200];

            // Audit trail: one structured entry per event, easy to ship to a SIEM
            _logger.LogInformation("Security audit: {SecurityEvent} for user {UserId} from {Ip} ({UserAgent})",
                securityEvent, user.Id, ip, userAgent);

            var to = overrideEmail ?? user.Email;
            if (!_options.CurrentValue.SendSecurityNotifications || string.IsNullOrEmpty(to))
                return Task.CompletedTask;

            var (subject, text) = Describe(securityEvent);
            _emailQueue.Enqueue(to, subject, EmailTemplates.SecurityNotification(subject, text, DateTimeOffset.UtcNow, ip, userAgent));
            return Task.CompletedTask;
        }

        private static (string Subject, string Text) Describe(SecurityEvent securityEvent) => securityEvent switch
        {
            SecurityEvent.PasswordChanged => ("Your password was changed", "The password for your account was just changed."),
            SecurityEvent.PasswordReset => ("Your password was reset", "The password for your account was reset using a password reset link."),
            SecurityEvent.PasswordSet => ("A password was added to your account", "A password was added to your account, so it can now be used to log in."),
            SecurityEvent.EmailChangeRequested => ("Email change requested", "Someone asked to change the email address of your account. It will only change once the new address is confirmed."),
            SecurityEvent.EmailChanged => ("Your email address was changed", "The email address of your account was changed. This address will no longer receive account emails."),
            SecurityEvent.TwoFactorEnabled => ("Two-factor authentication enabled", "Two-factor authentication was turned on for your account."),
            SecurityEvent.TwoFactorDisabled => ("Two-factor authentication disabled", "Two-factor authentication was turned off for your account."),
            SecurityEvent.AuthenticatorReset => ("Authenticator key reset", "The authenticator app key for your account was reset and two-factor authentication was turned off."),
            SecurityEvent.RecoveryCodesGenerated => ("New recovery codes generated", "New two-factor recovery codes were generated. Your old codes no longer work."),
            SecurityEvent.ExternalLoginAdded => ("New login method added", "An external login provider was linked to your account."),
            SecurityEvent.ExternalLoginRemoved => ("Login method removed", "An external login provider was removed from your account."),
            SecurityEvent.PasskeyAdded => ("New passkey added", "A new passkey was registered for your account."),
            SecurityEvent.PasskeyRemoved => ("Passkey removed", "A passkey was removed from your account."),
            SecurityEvent.SignedOutEverywhere => ("Signed out of all devices", "All other sessions of your account were signed out."),
            SecurityEvent.AccountLockedOut => ("Your account was locked", "Your account was temporarily locked after several failed login attempts."),
            SecurityEvent.AccountDeleted => ("Your account was deleted", "Your account and its personal data were permanently deleted."),
            _ => ("Security alert", "A security-relevant change was made to your account.")
        };
    }
}
