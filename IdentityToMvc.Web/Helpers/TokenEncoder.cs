using Microsoft.AspNetCore.WebUtilities;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace IdentityToMvc.Web.Helpers
{
    /// <summary>
    /// Encodes Identity tokens so they are safe to put in a URL and decodes them back.
    /// </summary>
    public static class TokenEncoder
    {
        public static string Encode(string token) =>
            WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

        /// <summary>
        /// Decodes a token produced by <see cref="Encode"/>. Returns <c>false</c> for
        /// malformed input (e.g. a truncated link) instead of throwing.
        /// </summary>
        public static bool TryDecode(string? encoded, [NotNullWhen(true)] out string? token)
        {
            token = null;
            if (string.IsNullOrWhiteSpace(encoded))
                return false;

            try
            {
                token = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(encoded));
                return true;
            }
            catch (FormatException)
            {
                return false;
            }
        }
    }
}
