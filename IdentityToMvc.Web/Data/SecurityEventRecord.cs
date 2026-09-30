namespace IdentityToMvc.Web.Data
{
    /// <summary>
    /// One row of the security audit log: what happened to which account, when, from where,
    /// and - for administrator actions - who did it.
    /// </summary>
    public class SecurityEventRecord
    {
        public long Id { get; set; }

        /// <summary>The account the event is about (kept as text so rows survive account deletion).</summary>
        public string? UserId { get; set; }
        public string? UserEmail { get; set; }

        /// <summary>Name of the <see cref="Security.SecurityEvent"/> value.</summary>
        public string Event { get; set; } = string.Empty;

        /// <summary>UTC.</summary>
        public DateTime CreatedAt { get; set; }
        public string? IpAddress { get; set; }
        public string? Device { get; set; }

        /// <summary>The administrator who performed the action, if it wasn't the user.</summary>
        public string? ActorUserId { get; set; }
        public string? ActorEmail { get; set; }

        public string? Details { get; set; }
    }
}
