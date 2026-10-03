using System.Globalization;
using Microsoft.AspNetCore.Localization;

namespace IdentityToMvc.Web.Localization
{
    public static class LocalizationSetup
    {
        public const string Serbian = "sr-Latn-RS";
        public const string English = "en";
        public const string CookieName = "__Host-IdentityToMvc.Culture";

        public static readonly CultureInfo[] SupportedCultures =
        [
#if (LangSr)
            new CultureInfo(Serbian),
#endif
#if (LangEn)
            new CultureInfo(English),
#endif
        ];

        /// <summary>Language picked in the switcher, then the browser language, then the configured default.</summary>
        public static RequestLocalizationOptions CreateOptions(IConfiguration configuration)
        {
            var defaultCulture = configuration["Localization:DefaultCulture"];
            if (string.IsNullOrWhiteSpace(defaultCulture)
                || !SupportedCultures.Any(c => c.Name.Equals(defaultCulture, StringComparison.OrdinalIgnoreCase)))
            {
                defaultCulture = SupportedCultures[0].Name;
            }

            var options = new RequestLocalizationOptions
            {
                DefaultRequestCulture = new RequestCulture(defaultCulture),
                SupportedCultures = SupportedCultures,
                SupportedUICultures = SupportedCultures,
                FallBackToParentCultures = true,
                FallBackToParentUICultures = true
            };
            options.RequestCultureProviders =
            [
                new CookieRequestCultureProvider { CookieName = CookieName },
                new BrowserLanguageProvider()
            ];
            return options;
        }

        /// <summary>
        /// Maps the browser's Accept-Language list to a supported culture. Serbian, Croatian,
        /// Bosnian and Montenegrin (any script) use the Serbian Latin translation.
        /// </summary>
        private sealed class BrowserLanguageProvider : RequestCultureProvider
        {
            private static readonly string[] SerbianLike = ["sr", "hr", "bs", "sh", "cnr"];

            public override Task<ProviderCultureResult?> DetermineProviderCultureResult(HttpContext httpContext)
            {
                var header = httpContext.Request.Headers.AcceptLanguage.ToString();
                foreach (var part in header.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    var tag = part.Split(';')[0].Trim().ToLowerInvariant();
                    var language = tag.Split('-')[0];
                    if (SerbianLike.Contains(language))
                        return Task.FromResult<ProviderCultureResult?>(new ProviderCultureResult(Serbian));
                    if (language == "en")
                        return Task.FromResult<ProviderCultureResult?>(new ProviderCultureResult(English));
                }
                return NullProviderCultureResult;
            }
        }
    }
}
