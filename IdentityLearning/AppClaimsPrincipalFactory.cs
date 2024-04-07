using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace IdentityLearning
{
    public class AppClaimsPrincipalFactory : UserClaimsPrincipalFactory<IdentityUser>
    {
        public AppClaimsPrincipalFactory(UserManager<IdentityUser> userManager, IOptions<IdentityOptions> optionsAccessor)
            : base(userManager, optionsAccessor)
        {
        }

        public override async Task<ClaimsPrincipal> CreateAsync(IdentityUser user)
        {
            var claims = new List<Claim>
            {
                new Claim(AppClaims.Name, user.UserName),
            };
            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

            return new ClaimsPrincipal(claimsIdentity);
        }
    }
}
