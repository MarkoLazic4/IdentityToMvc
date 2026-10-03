using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;

namespace IdentityToMvc.Web.Areas.User.ViewModels.Account
{
    public class LoginWithRecoveryCodeViewModel
    {
        public InputModel Input { get; set; } = new();
        public string? ReturnUrl { get; set; } = null;


        public class InputModel
        {
            [BindProperty]
            [Required(ErrorMessage = "The {0} field is required.")]
            [DataType(DataType.Text)]
            [Display(Name = "Recovery code")]
            public string RecoveryCode { get; set; } = string.Empty;
        }
    }
}
