using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace IdentityLearning
{
    [Route("v3")]
    public class V3Controller : Controller
    {
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

            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("8YWhIKD4lX9CLVrmRSxq8YWhIKD4lX9CLVrmRSxq"));
            var token = new JwtSecurityToken(
                issuer: "https://localhost:7058",
                audience: "https://localhost:7058",
                claims: claims,
                expires: DateTime.UtcNow.Add(TimeSpan.FromHours(1)),
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256));

            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            Response.Cookies.Append("Token", tokenString);

            return RedirectToAction(nameof(ProtectedPage));
        }

        [AllowAnonymous]
        [HttpGet("log-out")]
        public async Task<IActionResult> LogOut()
        {
            await HttpContext.SignOutAsync(Policies.Authentification.V3);

            return RedirectToAction(nameof(PublicPage));
        }

        [Authorize(Policy = Policies.Authorization.Authorized, AuthenticationSchemes = Policies.Authentification.V3)]
        [HttpGet("protected-page")]
        public async Task<IActionResult> ProtectedPage()
        {
            return Ok("Protected page");
        }

        [Authorize(Roles = "User", AuthenticationSchemes = Policies.Authentification.V3)]
        [HttpGet("user-page")]
        public async Task<IActionResult> UserPage()
        {
            return Ok("User page");
        }

        [Authorize(Roles = "Admin", AuthenticationSchemes = Policies.Authentification.V3)]
        [HttpGet("admin-page")]
        public async Task<IActionResult> AdminPage()
        {
            return Ok("Admin page");
        }

        [Authorize(Policy = Policies.Authorization.HasNameClaim, AuthenticationSchemes = Policies.Authentification.V3)]
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
    }
}
