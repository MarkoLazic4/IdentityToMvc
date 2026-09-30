using Microsoft.AspNetCore.Identity;

namespace IdentityToMvc.Web.Security
{
    /// <summary>
    /// Identity skips the (deliberately slow) password hash check when the account doesn't exist,
    /// is unconfirmed or locked out. Without compensation a login attempt answers in ~0.1s for an
    /// unknown email and ~0.6s for an existing one, which reveals who has an account.
    /// This runs an equivalent hash operation against a throw-away hash so every path costs the same.
    /// </summary>
    public sealed class PasswordTimingEqualizer
    {
        private static readonly IdentityUser DummyUser = new() { UserName = "timing-equalizer" };
        private static readonly object HashLock = new();
        // Computed once per process: creating it costs as much as a hash itself
        private static string? _dummyHash;

        private readonly IPasswordHasher<IdentityUser> _hasher;

        public PasswordTimingEqualizer(IPasswordHasher<IdentityUser> hasher)
        {
            _hasher = hasher;
        }

        /// <summary>Costs the same as verifying a real password.</summary>
        public void VerifyDummy(string? password)
        {
            if (_dummyHash == null)
            {
                lock (HashLock)
                {
                    _dummyHash ??= _hasher.HashPassword(DummyUser, Guid.NewGuid().ToString("N"));
                }
            }
            _hasher.VerifyHashedPassword(DummyUser, _dummyHash, password ?? string.Empty);
        }

        /// <summary>Costs the same as hashing a new password (e.g. creating an account).</summary>
        public void HashDummy(string? password) =>
            _hasher.HashPassword(DummyUser, password ?? string.Empty);
    }
}
