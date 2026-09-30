using System.ComponentModel.DataAnnotations;

namespace IdentityToMvc.Web.Areas.User.ViewModels.Manage
{
    public class ChangeEmailViewModel
    {
        public string? Email { get; set; }

        public bool IsEmailConfirmed { get; set; }

        public InputModel Input { get; set; } = new();


        public class InputModel
        {
            [Required(ErrorMessage = "The {0} field is required.")]
            [EmailAddress(ErrorMessage = "The {0} field is not a valid e-mail address.")]
            [Display(Name = "New email")]
            public string NewEmail { get; set; } = string.Empty;
        }
    }
}
