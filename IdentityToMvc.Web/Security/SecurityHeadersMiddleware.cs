using System.Security.Cryptography;

namespace IdentityToMvc.Web.Security
{
    /// <summary>
    /// Adds hardening headers to every response, including a strict Content Security Policy
    /// that only allows scripts from this origin or inline scripts carrying the per-request nonce.
    /// </summary>
    public sealed class SecurityHeadersMiddleware
    {
        internal const string NonceItemKey = "csp-nonce";

        // External login challenges redirect the browser from a form POST to the provider;
        // form-action also applies to those redirects, so the providers must be allowed.
#if (Google && Facebook)
        private const string ExternalLoginOrigins =
            " https://accounts.google.com https://www.facebook.com https://m.facebook.com";
#elif (Google)
        private const string ExternalLoginOrigins = " https://accounts.google.com";
#elif (Facebook)
        private const string ExternalLoginOrigins = " https://www.facebook.com https://m.facebook.com";
#else
        private const string ExternalLoginOrigins = "";
#endif

        private readonly RequestDelegate _next;
        private readonly IHostEnvironment _environment;

        public SecurityHeadersMiddleware(RequestDelegate next, IHostEnvironment environment)
        {
            _next = next;
            _environment = environment;
        }

        public Task InvokeAsync(HttpContext context)
        {
            var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
            context.Items[NonceItemKey] = nonce;

            context.Response.OnStarting(() =>
            {
                var headers = context.Response.Headers;

                // In Development allow the Visual Studio Browser Link / hot reload connections
                var devConnect = _environment.IsDevelopment() ? " ws: wss: http://localhost:* https://localhost:*" : string.Empty;
                var devScript = _environment.IsDevelopment() ? " http://localhost:* https://localhost:*" : string.Empty;

                var csp =
                    "default-src 'self'; " +
                    $"script-src 'self' 'nonce-{nonce}'{devScript}; " +
                    // No inline <style> or style="" attributes (scripts may still set element.style)
                    "style-src 'self'; " +
                    "img-src 'self' data:; " +
                    "font-src 'self'; " +
                    $"connect-src 'self'{devConnect}; " +
                    $"form-action 'self'{ExternalLoginOrigins}; " +
                    "frame-ancestors 'none'; " +
                    "base-uri 'self'; " +
                    "object-src 'none'";
                if (context.Request.IsHttps)
                {
                    csp += "; upgrade-insecure-requests";
                }

                headers.ContentSecurityPolicy = csp;
                headers.XContentTypeOptions = "nosniff";
                headers.XFrameOptions = "DENY";
                headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
                headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()";
                headers["Cross-Origin-Opener-Policy"] = "same-origin";
                headers["Cross-Origin-Resource-Policy"] = "same-origin";

                // Account pages and anything shown to a signed-in user must never be cached,
                // otherwise the back button can reveal them after logout on a shared computer.
                // Static assets keep their normal caching.
                var isHtml = context.Response.ContentType?.StartsWith("text/html", StringComparison.OrdinalIgnoreCase) == true;
                if (isHtml && (context.User.Identity?.IsAuthenticated == true
                    || context.Request.Path.StartsWithSegments("/User")))
                {
                    headers.CacheControl = "no-store, no-cache";
                    headers.Pragma = "no-cache";
                }

                return Task.CompletedTask;
            });

            return _next(context);
        }
    }

    public static class CspNonceExtensions
    {
        /// <summary>
        /// The nonce that inline &lt;script&gt; blocks must carry to be allowed by the CSP.
        /// </summary>
        public static string GetCspNonce(this HttpContext context) =>
            context.Items[SecurityHeadersMiddleware.NonceItemKey] as string ?? string.Empty;
    }
}
