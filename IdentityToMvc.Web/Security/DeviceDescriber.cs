namespace IdentityToMvc.Web.Security
{
    /// <summary>
    /// Turns a browser User-Agent string into a short description such as "Chrome on Windows".
    /// Good enough to recognise your own devices; not meant for analytics.
    /// </summary>
    public static class DeviceDescriber
    {
        public static string Describe(string? userAgent)
        {
            if (string.IsNullOrWhiteSpace(userAgent))
                return "Unknown device";

            var ua = userAgent;
            var browser =
                Has(ua, "Edg/") ? "Edge" :
                Has(ua, "OPR/") || Has(ua, "Opera") ? "Opera" :
                Has(ua, "Firefox/") ? "Firefox" :
                Has(ua, "HeadlessChrome") ? "Headless Chrome" :
                Has(ua, "Chrome/") || Has(ua, "CriOS/") ? "Chrome" :
                Has(ua, "Safari/") ? "Safari" :
                "Browser";

            var os =
                Has(ua, "Windows") ? "Windows" :
                Has(ua, "iPhone") || Has(ua, "iPad") ? "iOS" :
                Has(ua, "Mac OS X") || Has(ua, "Macintosh") ? "macOS" :
                Has(ua, "Android") ? "Android" :
                Has(ua, "CrOS") ? "ChromeOS" :
                Has(ua, "Linux") ? "Linux" :
                "unknown OS";

            return $"{browser} · {os}";
        }

        private static bool Has(string value, string part) => value.Contains(part, StringComparison.OrdinalIgnoreCase);
    }
}
