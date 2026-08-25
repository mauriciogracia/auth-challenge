using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Collaborate.Auth.Api.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

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
        ValidateAudience = true,
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

// 3. Swagger / OpenAPI Configuration
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Collaborate Identity & Authorization API",
        Version = "v1",
        Description = "OAuth 2.0 / RFC 8693 Token Exchange & Downstream Protected Resources"
    });

    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "Enter your JWT token (e.g. Bearer {token})"
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

// Enable Swagger UI and serve at application root ("/")
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "Collaborate Auth API v1");
    c.RoutePrefix = string.Empty;
});

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.MapGet("/health", () => Results.Ok(new
{
    Service = "Collaborate Identity & Authorization Platform",
    Status = "Healthy",
    Version = "1.0.0"
}));

app.Run();

// Make Program class accessible to WebApplicationFactory for integration tests
public partial class Program { }
