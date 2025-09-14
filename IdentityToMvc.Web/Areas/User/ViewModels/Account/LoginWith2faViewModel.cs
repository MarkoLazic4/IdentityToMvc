using System.ComponentModel.DataAnnotations;

namespace IdentityToMvc.Web.Areas.User.ViewModels.Account
{
    public class LoginWith2faViewModel
    {
        public InputModel Input { get; set; } = new();
        public bool RememberMe { get; set; }
        public string? ReturnUrl { get; set; } = null;


        public class InputModel
        {
            [Required]
            [StringLength(7, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
            [DataType(DataType.Text)]
            [Display(Name = "Authenticator code")]
            public string TwoFactorCode { get; set; } = string.Empty;

            [Display(Name = "Remember this machine")]
            public bool RememberMachine { get; set; }
        }
    }
}
