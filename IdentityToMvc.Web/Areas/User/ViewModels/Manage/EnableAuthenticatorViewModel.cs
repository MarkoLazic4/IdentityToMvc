using System.ComponentModel.DataAnnotations;

namespace IdentityToMvc.Web.Areas.User.ViewModels.Manage
{
    public class EnableAuthenticatorViewModel
    {
        public string SharedKey { get; set; } = string.Empty;
        public string AuthenticatorUri { get; set; } = string.Empty;

        public InputModel Input { get; set; } = new();


        public class InputModel
        {
            [Required(ErrorMessage = "The {0} field is required.")]
            [StringLength(7, ErrorMessage = "The {0} must be at least {2} and at max {1} characters long.", MinimumLength = 6)]
            [DataType(DataType.Text)]
            [Display(Name = "Verification code")]
            public string Code { get; set; } = string.Empty;
        }
    }
}
