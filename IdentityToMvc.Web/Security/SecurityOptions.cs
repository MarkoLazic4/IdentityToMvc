namespace IdentityToMvc.Web.Security
{
    /// <summary>
    /// Settings bound from the "Security" configuration section.
    /// Every optional feature can be switched off here without touching the code,
    /// so the same template works for simple and for security-sensitive apps.
    /// </summary>
    public sealed class SecurityOptions
    {
#if (TwoFactor)
        /// <summary>Two-factor authentication (authenticator app + recovery codes) in Manage account.</summary>
        public bool EnableTwoFactor { get; set; } = true;
#endif

#if (Passkeys)
        /// <summary>Passkey (WebAuthn) login and the Manage account > Passkeys page.</summary>
        public bool EnablePasskeys { get; set; } = true;
#endif

        /// <summary>"Sudo mode": ask for the password again before sensitive changes.</summary>
        public bool RequireRecentAuthentication { get; set; } = true;

        /// <summary>Per-IP limits on account form posts and email-sending endpoints.</summary>
        public bool EnableRateLimiting { get; set; } = true;

#if (BreachedPasswords)
        /// <summary>Check new passwords against the Have I Been Pwned breach corpus.</summary>
        public bool CheckBreachedPasswords { get; set; } = true;
#endif

#if (Notifications)
        /// <summary>Send an email to the user when security-relevant changes happen on their account.</summary>
        public bool SendSecurityNotifications { get; set; } = true;
#endif

#if (Passkeys)
        /// <summary>Maximum number of passkeys a user can register.</summary>
        public int MaxPasskeysPerUser { get; set; } = 10;
#endif
    }

    public enum SecurityFeature
    {
#if (TwoFactor)
        TwoFactor,
#endif
#if (Passkeys)
        Passkeys,
#endif
    }

    public static class SecurityOptionsExtensions
    {
        public static bool IsEnabled(this SecurityOptions options, SecurityFeature feature) => feature switch
        {
#if (TwoFactor)
            SecurityFeature.TwoFactor => options.EnableTwoFactor,
#endif
#if (Passkeys)
            SecurityFeature.Passkeys => options.EnablePasskeys,
#endif
            _ => true
        };
    }
}
