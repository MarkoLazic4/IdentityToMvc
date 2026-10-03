using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Localization;

namespace IdentityToMvc.Web.Security
{
    /// <summary>
    /// Rejects passwords that contain the user's email / user name.
    /// </summary>
    public sealed class UserInfoPasswordValidator : IPasswordValidator<IdentityUser>
    {
        private readonly IStringLocalizer<SharedResource> _t;

        public UserInfoPasswordValidator(IStringLocalizer<SharedResource> localizer)
        {
            _t = localizer;
        }

        public Task<IdentityResult> ValidateAsync(UserManager<IdentityUser> manager, IdentityUser user, string? password)
        {
            if (string.IsNullOrEmpty(password))
                return Task.FromResult(IdentityResult.Success);

            var candidates = new[] { user.UserName, user.Email, user.Email?.Split('@')[0] };
            foreach (var value in candidates)
            {
                if (!string.IsNullOrEmpty(value) && value.Length >= 3
                    && password.Contains(value, StringComparison.OrdinalIgnoreCase))
                {
                    return Task.FromResult(IdentityResult.Failed(new IdentityError
                    {
                        Code = "PasswordContainsUserInfo",
                        Description = _t["Your password must not contain your email address or user name."]
                    }));
                }
            }

            return Task.FromResult(IdentityResult.Success);
        }
    }
}
