namespace IdentityToMvc.Web.Data
{
    /// <summary>
    /// A signed-in browser/device. The auth cookie carries the session id ("sid" claim); a session
    /// that is revoked here is signed out on its next request, which powers "sign out this device".
    /// </summary>
    public class UserSession
    {
        public string Id { get; set; } = string.Empty;
        public string UserId { get; set; } = string.Empty;
        /// <summary>UTC.</summary>
        public DateTime CreatedAt { get; set; }
        public DateTime LastSeenAt { get; set; }
        public string? IpAddress { get; set; }

        /// <summary>Friendly device description, e.g. "Chrome on Windows".</summary>
        public string? Device { get; set; }
        public DateTime? RevokedAt { get; set; }
    }
}
