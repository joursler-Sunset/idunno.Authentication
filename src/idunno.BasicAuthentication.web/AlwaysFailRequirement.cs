using Microsoft.AspNet.Authorization;

namespace idunno.BasicAuthentication.Web
{
    public class AlwaysFailRequirement : AuthorizationHandler<AlwaysFailRequirement>, IAuthorizationRequirement
    {
        protected override void Handle(AuthorizationContext context, AlwaysFailRequirement requirement)
        {
            return;
        }
    }
}
