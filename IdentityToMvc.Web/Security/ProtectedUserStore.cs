using System.Security.Cryptography;
using System.Text;
using IdentityToMvc.Web.Data;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace IdentityToMvc.Web.Security
{
    /// <summary>
    /// The default Identity store keeps the authenticator (TOTP) secret and the 2FA recovery codes
    /// as plain text in AspNetUserTokens - anyone with a copy of the database could generate valid
    /// 2FA codes. This store:
    /// <list type="bullet">
    /// <item>encrypts the authenticator key with ASP.NET Core Data Protection;</item>
    /// <item>keeps only PBKDF2 hashes of recovery codes (like passwords - they are never needed again).</item>
    /// </list>
    /// Values written by the default store are still accepted and get upgraded when they change.
    /// </summary>
    public sealed class ProtectedUserStore : UserStore<IdentityUser, IdentityRole, ApplicationDbContext, string,
        IdentityUserClaim<string>, IdentityUserRole<string>, IdentityUserLogin<string>, IdentityUserToken<string>,
        IdentityRoleClaim<string>, IdentityUserPasskey<string>>
    {
        private const string EncryptedPrefix = "enc:";
        private const string HashedPrefix = "h1:";
        private const int RecoveryCodeIterations = 50_000;

        private readonly IDataProtector _protector;

        public ProtectedUserStore(ApplicationDbContext context, IDataProtectionProvider dataProtection,
            IdentityErrorDescriber? describer = null) : base(context, describer)
        {
            _protector = dataProtection.CreateProtector("IdentityToMvc.UserStore.AuthenticatorKey");
        }

        public override Task SetAuthenticatorKeyAsync(IdentityUser user, string key, CancellationToken cancellationToken)
            => base.SetAuthenticatorKeyAsync(user, EncryptedPrefix + _protector.Protect(key), cancellationToken);

        public override async Task<string?> GetAuthenticatorKeyAsync(IdentityUser user, CancellationToken cancellationToken)
        {
            var stored = await base.GetAuthenticatorKeyAsync(user, cancellationToken);
            if (stored == null || !stored.StartsWith(EncryptedPrefix, StringComparison.Ordinal))
                return stored; // legacy plain-text value

            return _protector.Unprotect(stored[EncryptedPrefix.Length..]);
        }

        public override Task ReplaceCodesAsync(IdentityUser user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken)
            => base.ReplaceCodesAsync(user, recoveryCodes.Select(code => HashCode(user, code)).ToList(), cancellationToken);

        public override async Task<bool> RedeemCodeAsync(IdentityUser user, string code, CancellationToken cancellationToken)
        {
            // The base implementation removes the matching entry, so pass the hash of the code;
            // fall back to the plain code for recovery codes created before hashing was enabled.
            return await base.RedeemCodeAsync(user, HashCode(user, code), cancellationToken)
                || await base.RedeemCodeAsync(user, code, cancellationToken);
        }

        private static string HashCode(IdentityUser user, string code)
        {
            var normalized = code.Trim().ToUpperInvariant();
            var salt = SHA256.HashData(Encoding.UTF8.GetBytes("IdentityToMvc.RecoveryCode:" + user.Id));
            var hash = Rfc2898DeriveBytes.Pbkdf2(normalized, salt, RecoveryCodeIterations, HashAlgorithmName.SHA256, 32);
            // Base64 never contains ';' (the separator used to store the list)
            return HashedPrefix + Convert.ToBase64String(hash);
        }
    }
}
