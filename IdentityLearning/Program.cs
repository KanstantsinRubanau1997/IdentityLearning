using System.Text;
using IdentityLearning;
using IdentityLearning.HealthChecks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<ApplicationDbContext>(
    options => options.UseInMemoryDatabase("ApplicationDb"));
builder.Services.AddIdentity<IdentityUser, IdentityRole>()
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddClaimsPrincipalFactory<AppClaimsPrincipalFactory>();

builder.Services.AddAuthentication()
    .AddCookie(Policies.Authentification.V1, options =>
    {
        options.LoginPath = new PathString("/v1/log-in");
        options.AccessDeniedPath = new PathString("/v1/log-in");
    })
    .AddCookie(Policies.Authentification.V2, options =>
     {
         options.LoginPath = new PathString("/v2/log-in");
         options.AccessDeniedPath = new PathString("/v2/log-in");
     })
    .AddJwtBearer(Policies.Authentification.V3, options =>
    {
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                context.Token = context.Request.Cookies["Token"];
                return Task.CompletedTask;
            },
            OnAuthenticationFailed = context =>
            {
                context.Response.Redirect(new PathString("/v3/log-in"));
                return Task.CompletedTask;
            },
            OnForbidden = context =>
            {
                context.Response.Redirect(new PathString("/v3/log-in"));
                return Task.CompletedTask;
            }
        };

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "https://localhost:7058",
            ValidateAudience = true,
            ValidAudience = "https://localhost:7058",
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("8YWhIKD4lX9CLVrmRSxq8YWhIKD4lX9CLVrmRSxq")),
            ValidateIssuerSigningKey = true,
            ValidateLifetime = true,
        };
    });
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy(Policies.Authorization.Authorized, policy => policy.RequireAuthenticatedUser());

    options.AddPolicy(Policies.Authorization.HasNameClaim, policy => policy.RequireClaim(AppClaims.Name));
});

builder.Services.ConfigureApplicationCookie(options =>
{
    options.ForwardDefaultSelector = (context) => Policies.Authentification.V1;
});

builder.Services.AddControllersWithViews();
builder.Services.AddMvc();

builder.Services.AddSwaggerGen();

builder.Services.Configure<IdentityOptions>(options =>
{
    options.Password.RequireDigit = false;
    options.Password.RequireLowercase = false;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = false;
    options.Password.RequiredLength = 6;
    options.Password.RequiredUniqueChars = 0;
});

builder.Services.AddHealthChecks()
    .AddCheck<SampleHealthCheck>("Sample")
    .AddCheck("Unhealthy", () => HealthCheckResult.Unhealthy("not working ((("))
    .AddCheck("Degraded", () => HealthCheckResult.Degraded(), tags: ["Degraded"])
    .AddDbContextCheck<ApplicationDbContext>(tags: ["Database"]);

builder.Services.Configure<HealthCheckPublisherOptions>(options =>
{
    options.Delay = TimeSpan.FromSeconds(1);
    options.Period = TimeSpan.FromSeconds(10);
});
builder.Services.AddSingleton<IHealthCheckPublisher, SampleHealthCheckPublisher>();

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();
app.MapSwagger();

app.UseCookiePolicy(new CookiePolicyOptions { MinimumSameSitePolicy = SameSiteMode.Strict });

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapHealthChecks("/healthz/Degraded", new HealthCheckOptions
{
    Predicate = healthCheck => healthCheck.Tags.Contains("Degraded")
}).RequireAuthorization(Policies.Authorization.HasNameClaim);

app.MapHealthChecks("/healthz", new HealthCheckOptions
{
    Predicate = healthCheck => healthCheck.Name == "Sample"
});

app.MapHealthChecks("/healthz/Unhealthy", new HealthCheckOptions
{
    Predicate = healthCheck => healthCheck.Name == "Unhealthy"
});

app.MapHealthChecks("/healthz/Database", new HealthCheckOptions
{
    Predicate = healthCheck => healthCheck.Name == "Database"
});

app.MapControllers();

app.Run();
