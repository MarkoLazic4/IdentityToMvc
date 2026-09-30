using System.ComponentModel.DataAnnotations;

namespace IdentityToMvc.Web.Areas.User.ViewModels.Manage
{
    public class IndexViewModel
    {
        [Display(Name = "Username")]
        public string Username { get; set; } = string.Empty;

        public InputModel Input { get; set; } = new();


        public class InputModel
        {
            [Phone(ErrorMessage = "The {0} field is not a valid phone number.")]
            [Display(Name = "Phone number")]
            public string? PhoneNumber { get; set; }
        }
    }
}
