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
            [Required(ErrorMessage = "The {0} field is required.")]
            [EmailAddress(ErrorMessage = "The {0} field is not a valid e-mail address.")]
            [Display(Name = "Email")]
            public string Email { get; set; } = string.Empty;

            [Required(ErrorMessage = "The {0} field is required.")]
            [DataType(DataType.Password)]
            [Display(Name = "Password")]
            public string Password { get; set; } = string.Empty;

            [Display(Name = "Remember me")]
            public bool RememberMe { get; set; }
        }
    }
}
