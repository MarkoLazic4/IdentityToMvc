namespace IdentityToMvc.Web.Security
{
    /// <summary>
    /// Settings bound from the "Security" configuration section.
    /// </summary>
    public sealed class SecurityOptions
    {
        /// <summary>Check new passwords against the Have I Been Pwned breach corpus.</summary>
        public bool CheckBreachedPasswords { get; set; } = true;

        /// <summary>Send an email to the user when security-relevant changes happen on their account.</summary>
        public bool SendSecurityNotifications { get; set; } = true;

        /// <summary>Maximum number of passkeys a user can register.</summary>
        public int MaxPasskeysPerUser { get; set; } = 10;
    }
}
