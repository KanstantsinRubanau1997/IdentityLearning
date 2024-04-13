using IdentityLearning.Identity;
using Microsoft.AspNetCore.Authorization;

namespace IdentityLearning.Authorization
{
    public class HasLetterAInNameAndRoleAuthorizationHandler : AuthorizationHandler<HasLetterAInNameAndRoleRequirenment, User>
    {
        protected override Task HandleRequirementAsync(AuthorizationHandlerContext context, HasLetterAInNameAndRoleRequirenment requirement, User resource)
        {
            var hasAllData = !string.IsNullOrEmpty(resource.Name)
                && resource.Role != null
                && !string.IsNullOrEmpty(resource.Role.Name);
            if (hasAllData && resource.Name.ToLower().Contains('a') && resource.Role.Name.ToLower().Contains('a'))
            {
                context.Succeed(requirement);
            }

            return Task.CompletedTask;
        }
    }
}
