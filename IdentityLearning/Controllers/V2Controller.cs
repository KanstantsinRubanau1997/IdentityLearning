﻿using IdentityLearning.Identity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

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
            };
            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
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
    }
}
