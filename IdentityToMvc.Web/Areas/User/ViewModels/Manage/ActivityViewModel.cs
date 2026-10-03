using IdentityToMvc.Web.Data;

namespace IdentityToMvc.Web.Areas.User.ViewModels.Manage
{
    public class ActivityViewModel
    {
        public IList<SecurityEventRecord> Events { get; set; } = new List<SecurityEventRecord>();
    }
}
