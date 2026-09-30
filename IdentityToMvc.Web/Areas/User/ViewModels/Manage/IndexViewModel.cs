using System.ComponentModel.DataAnnotations;

namespace IdentityToMvc.Web.Areas.User.ViewModels.Manage
{
    public class IndexViewModel
    {
        public string Username { get; set; } = string.Empty;

        public InputModel Input { get; set; } = new();


        public class InputModel
        {
            [Phone]
            [Display(Name = "Phone number")]
            public string? PhoneNumber { get; set; }
        }
    }
}
