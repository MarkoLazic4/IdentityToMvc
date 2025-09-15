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
            [Required]
            [DataType(DataType.Text)]
            [Display(Name = "Recovery Code")]
            public string RecoveryCode { get; set; } = string.Empty;
        }
    }
}
