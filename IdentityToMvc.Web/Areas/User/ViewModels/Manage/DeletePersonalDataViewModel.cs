using System.ComponentModel.DataAnnotations;

namespace IdentityToMvc.Web.Areas.User.ViewModels.Manage
{
    public class DeletePersonalDataViewModel
    {
        public InputModel Input { get; set; } = new();

        public bool RequirePassword { get; set; }
        

        public class InputModel
        {
            [Required(ErrorMessage = "The {0} field is required.")]
            [DataType(DataType.Password)]
            [Display(Name = "Password")]
            public string Password { get; set; } = string.Empty;
        }
    }
}
