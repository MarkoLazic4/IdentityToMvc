using Microsoft.AspNetCore.Identity;
using System.Globalization;
using System.Text;
using System.Text.Encodings.Web;

namespace IdentityToMvc.Web.Helpers
{
    public static class AuthenticatorHelper
    {
        private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

        public static async Task<(string sharedKey, string authenticatorUri)> LoadSharedKeyAndQrCodeUriAsync(
            UserManager<IdentityUser> userManager, UrlEncoder urlEncoder, IdentityUser user)
        {
            if (userManager == null) 
                throw new ArgumentNullException(nameof(userManager));
            if (urlEncoder == null) 
                throw new ArgumentNullException(nameof(urlEncoder));
            if (user == null) 
                throw new ArgumentNullException(nameof(user));

            var unformattedKey = await userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(unformattedKey))
            {
                await userManager.ResetAuthenticatorKeyAsync(user);
                unformattedKey = await userManager.GetAuthenticatorKeyAsync(user);
            }

            var sharedKey = FormatKey(unformattedKey);
            var email = await userManager.GetEmailAsync(user);
            var uri = GenerateQrCodeUri(urlEncoder, email, unformattedKey);

            return (sharedKey: sharedKey, authenticatorUri: uri);
        }

        private static string FormatKey(string unformattedKey)
        {
            if (string.IsNullOrEmpty(unformattedKey)) 
                return string.Empty;

            var result = new StringBuilder();
            int currentPosition = 0;
            while (currentPosition + 4 < unformattedKey.Length)
            {
                result.Append(unformattedKey.AsSpan(currentPosition, 4)).Append(' ');
                currentPosition += 4;
            }
            if (currentPosition < unformattedKey.Length)
            {
                result.Append(unformattedKey.AsSpan(currentPosition));
            }

            return result.ToString().ToLowerInvariant();
        }

        private static string GenerateQrCodeUri(UrlEncoder urlEncoder, string email, string unformattedKey)
        {
            return string.Format(
                CultureInfo.InvariantCulture,
                AuthenticatorUriFormat,
                urlEncoder.Encode("Microsoft.AspNetCore.Identity.UI"),
                urlEncoder.Encode(email ?? string.Empty),
                unformattedKey);
        }
    }
}
