using IdentityToMvc.Web.Data;
using IdentityToMvc.Web.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Options;

namespace IdentityToMvc.Web.Security
{
    public enum SecurityEvent
    {
        SignedIn,
        LoginFailed,
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
        SessionRevoked,
        SignedOutEverywhere,
        AccountLockedOut,
        AccountUnlocked,
        AccountDeleted,
        AdminLockedAccount,
        AdminUnlockedAccount,
        AdminSignedOutUser,
        AdminResetTwoFactor,
        AdminChangedRoles,
        AdminConfirmedEmail,
        AdminDeletedAccount
    }

    /// <summary>
    /// Writes an audit record (database + structured log) for security-relevant account changes and
    /// emails the account owner, so a hijacked account is noticed quickly.
    /// </summary>
    public interface ISecurityNotifier
    {
        /// <param name="overrideEmail">Send the email to this address instead of the user's current one
        /// (e.g. the old address after an email change).</param>
        /// <param name="sendEmail">False to only write the audit entry.</param>
        /// <param name="actor">The administrator who performed the action, if it wasn't the user.</param>
        Task NotifyAsync(IdentityUser user, SecurityEvent securityEvent, string? overrideEmail = null,
            bool sendEmail = true, IdentityUser? actor = null, string? details = null);
    }

    public sealed class SecurityNotifier : ISecurityNotifier
    {
        // Events that are only recorded, never emailed (the user just did it, or it's noise)
        private static readonly HashSet<SecurityEvent> AuditOnly =
        [
            SecurityEvent.LoginFailed,
            SecurityEvent.SessionRevoked,
            SecurityEvent.AccountUnlocked,
            SecurityEvent.AdminConfirmedEmail
        ];

        private readonly ApplicationDbContext _db;
        private readonly IEmailQueue _emailQueue;
        private readonly EmailTemplates _templates;
        private readonly IHttpContextAccessor _httpContextAccessor;
        private readonly IOptionsMonitor<SecurityOptions> _options;
        private readonly IStringLocalizer<SharedResource> _t;
        private readonly ILogger<SecurityNotifier> _logger;

        public SecurityNotifier(ApplicationDbContext db, IEmailQueue emailQueue, EmailTemplates templates,
            IHttpContextAccessor httpContextAccessor, IOptionsMonitor<SecurityOptions> options,
            IStringLocalizer<SharedResource> localizer, ILogger<SecurityNotifier> logger)
        {
            _db = db;
            _emailQueue = emailQueue;
            _templates = templates;
            _httpContextAccessor = httpContextAccessor;
            _options = options;
            _t = localizer;
            _logger = logger;
        }

        public async Task NotifyAsync(IdentityUser user, SecurityEvent securityEvent, string? overrideEmail = null,
            bool sendEmail = true, IdentityUser? actor = null, string? details = null)
        {
            var httpContext = _httpContextAccessor.HttpContext;
            var ip = httpContext?.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var device = DeviceDescriber.Describe(httpContext?.Request.Headers.UserAgent.ToString());
            var now = DateTime.UtcNow;

            // Audit trail: structured log entry (easy to ship to a SIEM) + database row (shown in the UI)
            _logger.LogInformation("Security audit: {SecurityEvent} for user {UserId} from {Ip} ({Device}) by {ActorId}",
                securityEvent, user.Id, ip, device, actor?.Id ?? user.Id);

            _db.SecurityEvents.Add(new SecurityEventRecord
            {
                UserId = user.Id,
                UserEmail = Truncate(user.Email, 256),
                Event = securityEvent.ToString(),
                CreatedAt = now,
                IpAddress = Truncate(ip, 64),
                Device = Truncate(device, 128),
                ActorUserId = actor?.Id,
                ActorEmail = Truncate(actor?.Email, 256),
                Details = Truncate(details, 512)
            });
            await _db.SaveChangesAsync();

#if (Notifications)
            var to = overrideEmail ?? user.Email;
            if (!sendEmail || AuditOnly.Contains(securityEvent)
                || !_options.CurrentValue.SendSecurityNotifications || string.IsNullOrEmpty(to))
            {
                return;
            }

            var title = SecurityEventText.Title(securityEvent, _t);
            var text = SecurityEventText.Description(securityEvent, _t);
            _emailQueue.Enqueue(to, title, _templates.SecurityNotification(title, text, now, ip, device));
#endif
        }

        private static string? Truncate(string? value, int length) =>
            value == null || value.Length <= length ? value : value[..length];
    }

    /// <summary>Human-readable, translated texts for security events (emails and activity pages).</summary>
    public static class SecurityEventText
    {
        public static string Title(SecurityEvent securityEvent, IStringLocalizer t) => securityEvent switch
        {
            SecurityEvent.SignedIn => t["New sign-in to your account"],
            SecurityEvent.LoginFailed => t["Failed login attempt"],
            SecurityEvent.PasswordChanged => t["Your password was changed"],
            SecurityEvent.PasswordReset => t["Your password was reset"],
            SecurityEvent.PasswordSet => t["A password was added to your account"],
            SecurityEvent.EmailChangeRequested => t["Email change requested"],
            SecurityEvent.EmailChanged => t["Your email address was changed"],
            SecurityEvent.TwoFactorEnabled => t["Two-factor authentication enabled"],
            SecurityEvent.TwoFactorDisabled => t["Two-factor authentication disabled"],
            SecurityEvent.AuthenticatorReset => t["Authenticator key reset"],
            SecurityEvent.RecoveryCodesGenerated => t["New recovery codes generated"],
            SecurityEvent.ExternalLoginAdded => t["New login method added"],
            SecurityEvent.ExternalLoginRemoved => t["Login method removed"],
            SecurityEvent.PasskeyAdded => t["New passkey added"],
            SecurityEvent.PasskeyRemoved => t["Passkey removed"],
            SecurityEvent.SessionRevoked => t["Device signed out"],
            SecurityEvent.SignedOutEverywhere => t["Signed out of all devices"],
            SecurityEvent.AccountLockedOut => t["Your account was locked"],
            SecurityEvent.AccountUnlocked => t["Account unlocked"],
            SecurityEvent.AccountDeleted => t["Your account was deleted"],
            SecurityEvent.AdminLockedAccount => t["Your account was locked by an administrator"],
            SecurityEvent.AdminUnlockedAccount => t["Your account was unlocked by an administrator"],
            SecurityEvent.AdminSignedOutUser => t["An administrator signed you out of all devices"],
            SecurityEvent.AdminResetTwoFactor => t["An administrator reset your two-factor authentication"],
            SecurityEvent.AdminChangedRoles => t["Your roles were changed"],
            SecurityEvent.AdminConfirmedEmail => t["Email confirmed by an administrator"],
            SecurityEvent.AdminDeletedAccount => t["Your account was deleted by an administrator"],
            _ => t["Security alert"]
        };

        public static string Description(SecurityEvent securityEvent, IStringLocalizer t) => securityEvent switch
        {
            SecurityEvent.SignedIn => t["Your account was just used to sign in from a device we haven't seen before."],
            SecurityEvent.PasswordChanged => t["The password for your account was just changed."],
            SecurityEvent.PasswordReset => t["The password for your account was reset using a password reset link."],
            SecurityEvent.PasswordSet => t["A password was added to your account, so it can now be used to log in."],
            SecurityEvent.EmailChangeRequested => t["Someone asked to change the email address of your account. It will only change once the new address is confirmed."],
            SecurityEvent.EmailChanged => t["The email address of your account was changed. This address will no longer receive account emails."],
            SecurityEvent.TwoFactorEnabled => t["Two-factor authentication was turned on for your account."],
            SecurityEvent.TwoFactorDisabled => t["Two-factor authentication was turned off for your account."],
            SecurityEvent.AuthenticatorReset => t["The authenticator app key for your account was reset and two-factor authentication was turned off."],
            SecurityEvent.RecoveryCodesGenerated => t["New two-factor recovery codes were generated. Your old codes no longer work."],
            SecurityEvent.ExternalLoginAdded => t["An external login provider was linked to your account."],
            SecurityEvent.ExternalLoginRemoved => t["An external login provider was removed from your account."],
            SecurityEvent.PasskeyAdded => t["A new passkey was registered for your account."],
            SecurityEvent.PasskeyRemoved => t["A passkey was removed from your account."],
            SecurityEvent.SignedOutEverywhere => t["All other sessions of your account were signed out."],
            SecurityEvent.AccountLockedOut => t["Your account was temporarily locked after several failed login attempts."],
            SecurityEvent.AccountDeleted => t["Your account and its personal data were permanently deleted."],
            SecurityEvent.AdminLockedAccount => t["An administrator locked your account. You can't log in until it is unlocked."],
            SecurityEvent.AdminUnlockedAccount => t["An administrator unlocked your account. You can log in again."],
            SecurityEvent.AdminSignedOutUser => t["An administrator signed your account out of all devices."],
            SecurityEvent.AdminResetTwoFactor => t["An administrator turned off two-factor authentication and reset your authenticator key. Set it up again as soon as possible."],
            SecurityEvent.AdminChangedRoles => t["An administrator changed the roles of your account."],
            SecurityEvent.AdminDeletedAccount => t["An administrator permanently deleted your account."],
            _ => t["A security-relevant change was made to your account."]
        };

        /// <summary>Bootstrap icon and tone used to display the event.</summary>
        public static (string Icon, string Tone) Style(SecurityEvent securityEvent) => securityEvent switch
        {
            SecurityEvent.SignedIn => ("bi-box-arrow-in-right", "neutral"),
            SecurityEvent.LoginFailed or SecurityEvent.AccountLockedOut or SecurityEvent.AdminLockedAccount => ("bi-exclamation-octagon", "danger"),
            SecurityEvent.PasswordChanged or SecurityEvent.PasswordReset or SecurityEvent.PasswordSet => ("bi-key", "neutral"),
            SecurityEvent.EmailChangeRequested or SecurityEvent.EmailChanged => ("bi-envelope", "neutral"),
            SecurityEvent.TwoFactorEnabled or SecurityEvent.PasskeyAdded => ("bi-shield-check", "success"),
            SecurityEvent.TwoFactorDisabled or SecurityEvent.AuthenticatorReset or SecurityEvent.AdminResetTwoFactor => ("bi-shield-x", "warning"),
            SecurityEvent.PasskeyRemoved => ("bi-fingerprint", "warning"),
            SecurityEvent.SessionRevoked or SecurityEvent.SignedOutEverywhere or SecurityEvent.AdminSignedOutUser => ("bi-laptop", "neutral"),
            SecurityEvent.AccountDeleted or SecurityEvent.AdminDeletedAccount => ("bi-trash3", "danger"),
            _ => ("bi-shield", "neutral")
        };
    }
}
