using IdentityLearning.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Text;

namespace IdentityLearning.Controllers
{
    [Route("v1")]
    public class V1Controller : Controller
    {
        private readonly SignInManager<User> _signInManager;
        private readonly UserManager<User> _userManager;
        private readonly IAuthorizationService _authorizationService;

        public V1Controller(
            SignInManager<User> signInManager,
            IAuthorizationService authorizationService,
            UserManager<User> userManager)
        {
            _signInManager = signInManager;
            _authorizationService = authorizationService;
            _userManager = userManager;
        }


        [AllowAnonymous]
        [HttpGet("log-in")]
        public async Task<IActionResult> LogIn()
        {
            return View();
        }

        [AllowAnonymous]
        [HttpPost("log-in")]
        public async Task<IActionResult> LogIn(string login, string password)
        {
            var result = await _signInManager.PasswordSignInAsync(login, password, true, false);
            if (!result.Succeeded)
            {
                return RedirectToAction(nameof(LogIn));
            }

            return RedirectToAction(nameof(ProtectedPage));
        }

        [AllowAnonymous]
        [HttpGet("log-out")]
        public async Task<IActionResult> LogOut()
        {
            await _signInManager.SignOutAsync();

            return RedirectToAction(nameof(PublicPage));
        }

        [Authorize(
            Policy = Policies.Authorization.Authorized,
            AuthenticationSchemes = Policies.Authentification.V1)]
        [HttpGet("protected-page")]
        public async Task<IActionResult> ProtectedPage()
        {
            return Ok("Protected page");
        }

        [Authorize(Roles = "User", AuthenticationSchemes = Policies.Authentification.V1)]
        [HttpGet("user-page")]
        public async Task<IActionResult> UserPage()
        {
            return Ok("User page");
        }

        [Authorize(Roles = "Admin", AuthenticationSchemes = Policies.Authentification.V1)]
        [HttpGet("admin-page")]
        public async Task<IActionResult> AdminPage()
        {
            return Ok("Admin page");
        }

        [Authorize(
            Policy = Policies.Authorization.HasNameClaim,
            AuthenticationSchemes = Policies.Authentification.V1)]
        [HttpGet("claims-protected-page")]
        public async Task<IActionResult> ClaimsProtectedPage()
        {
            return Ok("Claims protected page");
        }

        [AllowAnonymous]
        [HttpGet("public-page")]
        public async Task<IActionResult> PublicPage()
        {
            return Ok("Public page");
        }

        [Authorize(
            Policy = Policies.Authorization.Authorized,
            AuthenticationSchemes = Policies.Authentification.V1)]
        [HttpGet("resource-based-page")]
        public async Task<IActionResult> ResourceBaseAuthorizedPage()
        {
            var user = await _userManager.GetUserAsync(User);
            var authorizationResult = await _authorizationService.AuthorizeAsync(
                User,
                user,
                Policies.Authorization.HasLetterAInNameAndRole);

            if (!authorizationResult.Succeeded)
            {
                return RedirectToAction(nameof(LogIn));
            }

            return Ok("Resource based page");
        }
    }
}
