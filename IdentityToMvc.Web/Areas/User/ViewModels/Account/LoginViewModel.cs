using Microsoft.AspNetCore.Authentication;
using System.ComponentModel.DataAnnotations;

namespace IdentityToMvc.Web.Areas.User.ViewModels.Account
{
    public class LoginViewModel
    {
        public InputModel Input { get; set; } = new();
        public IList<AuthenticationScheme> ExternalLogins { get; set; } = new List<AuthenticationScheme>();
        public string? ReturnUrl { get; set; } = null;


        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; } = string.Empty;

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; } = string.Empty;

            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }
    }
}
