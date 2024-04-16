using IdentityLearning.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Owin.Security.Cookies;
using System.Net;
using System.Security.Claims;
using System.Text;
using static System.Net.WebRequestMethods;

namespace IdentityLearning.Controllers
{
    [Route("v2")]
    public class V2Controller : Controller
    {
        private readonly IAuthorizationService _authorizationService;

        public V2Controller(IAuthorizationService authorizationService)
        {
            _authorizationService = authorizationService;
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
            if (login != "qwe" || password != "123")
            {
                return RedirectToAction(nameof(LogIn));
            }

            var claims = new List<Claim>
            {
                new Claim(AppClaims.Name, login),
                new Claim(ClaimTypes.Role, "Admin"),
                new Claim(ClaimTypes.DateOfBirth, "04-11-1997")
            };
            var claimsIdentity = new ClaimsIdentity(
                claims,
                Microsoft.AspNetCore.Authentication.Cookies.CookieAuthenticationDefaults.AuthenticationScheme);
            var claimsPrincipal = new ClaimsPrincipal(claimsIdentity);

            await HttpContext.SignInAsync(Policies.Authentification.V2, claimsPrincipal);

            return RedirectToAction(nameof(ProtectedPage));
        }

        [AllowAnonymous]
        [HttpGet("log-out")]
        public async Task<IActionResult> LogOut()
        {
            await HttpContext.SignOutAsync(Policies.Authentification.V2);

            return RedirectToAction(nameof(PublicPage));
        }

        [Authorize(Policy = Policies.Authorization.Authorized, AuthenticationSchemes = Policies.Authentification.V2)]
        [HttpGet("protected-page")]
        public async Task<IActionResult> ProtectedPage()
        {
            return Ok("Protected page");
        }

        [Authorize(Roles = "User", AuthenticationSchemes = Policies.Authentification.V2)]
        [HttpGet("user-page")]
        public async Task<IActionResult> UserPage()
        {
            return Ok("User page");
        }

        [Authorize(Roles = "Admin", AuthenticationSchemes = Policies.Authentification.V2)]
        [HttpGet("admin-page")]
        public async Task<IActionResult> AdminPage()
        {
            return Ok("Admin page");
        }

        [Authorize(Policy = Policies.Authorization.HasNameClaim, AuthenticationSchemes = Policies.Authentification.V2)]
        [HttpGet("claims-protected-page")]
        public async Task<IActionResult> ClaimsProtectedPage()
        {
            return Ok("Claims protected page");
        }

        [Authorize(Policy = Policies.Authorization.AtLeast21, AuthenticationSchemes = Policies.Authentification.V2)]
        [HttpGet("old-people-only-page")]
        public async Task<IActionResult> OldPeopleOnlyPage()
        {
            return Ok("Old people only page");
        }

        [AllowAnonymous]
        [HttpGet("public-page")]
        public async Task<IActionResult> PublicPage()
        {
            return Ok("Public page");
        }

        [Authorize(
            Policy = Policies.Authorization.Authorized,
            AuthenticationSchemes = Policies.Authentification.V2)]
        [HttpGet("resource-based-page")]
        public async Task<IActionResult> ResourceBaseAuthorizedPage()
        {
            var user = new User
            {
                Name = "a",
                Role = new Role { Name = "a" }
            };
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

        [Authorize(
            Policy = Policies.Authorization.Authorized,
            AuthenticationSchemes = Policies.Authentification.V2)]
        [HttpGet("decrypt-cookie")]
        public IActionResult DecryptCookie()
        {
            var cookie = HttpContext.Request.Cookies[".AspNetCore.V2"];

            var data = Convert.FromBase64String(cookie);
            var decodedString = Encoding.UTF8.GetString(data);
            //*
            //V2
            //Cookies
            //Name qwe
            //<http://schemas.microsoft.com/ws/2008/06/identity/claims/role Admin
            //.issuedTue, 16 Apr 2024 20:31:16 GMT
            //.expiresTue, 30 Apr 2024 20:31:16 GMT
            //*
            return Ok(decodedString);
        }
    }
}
