using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
namespace IdentityToMvc.Web.Areas.User.ViewModels.Manage
{
    public class ExternalLoginsViewModel
    {
        public IList<UserLoginInfo> CurrentLogins { get; set; } = new List<UserLoginInfo>();
        public IList<AuthenticationScheme> OtherLogins { get; set; } = new List<AuthenticationScheme>();
        public bool ShowRemoveButton { get; set; }
    }
}
