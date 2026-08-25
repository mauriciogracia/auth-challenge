using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Collaborate.Auth.Api.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

// Prevent Microsoft identity from remapping standard JWT claims ('sub', 'scp', etc.)
JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

var builder = WebApplication.CreateBuilder(args);


// 1. Dependency Injection: Data Abstraction Layer & Core Services
builder.Services.AddSingleton<IPermissionStore, FastPermissionStore>();
builder.Services.AddSingleton<ITokenExchangeService, TokenExchangeService>();


// 2. Authentication & JWT Bearer Configuration
var issuer = builder.Configuration["Auth:Issuer"] ?? "https://auth.collaborate.caseware.com";
var secret = builder.Configuration["Auth:SigningKey"] ?? "CollaborateSuperSecretKeyForTokenExchangeValidation2026!";
var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = issuer,
        ValidateAudience = true, // Strict audience validation (Confused Deputy protection)
        ValidAudiences = new[]
        {
            "https://api.caseware.com/collaborate",
            "https://api.caseware.com/notifications",
            "https://api.caseware.com/documents",
            "https://api.caseware.com/financial-data"
        },
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = signingKey,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromSeconds(30)
    };
});

builder.Services.AddAuthorization();
builder.Services.AddControllers();

var app = builder.Build();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.MapGet("/", () => Results.Ok(new
{
    Service = "Collaborate Identity & Authorization Platform",
    Status = "Healthy",
    Version = "1.0.0"
}));

app.Run();

// Make Program class accessible to WebApplicationFactory for integration tests
public partial class Program { }
