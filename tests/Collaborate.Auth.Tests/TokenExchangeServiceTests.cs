using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Collaborate.Auth.Api.Models;
using Collaborate.Auth.Api.Services;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Collaborate.Auth.Tests;

public class TokenExchangeServiceTests
{
    private readonly FastPermissionStore _permissionStore;
    private readonly IConfiguration _configuration;
    private readonly TokenExchangeService _tokenExchangeService;

    public TokenExchangeServiceTests()
    {
        _permissionStore = new FastPermissionStore();


        var configValues = new Dictionary<string, string?>
        {
            { "Auth:Issuer", "https://auth.collaborate.caseware.com" },
            { "Auth:SigningKey", "CollaborateSuperSecretKeyForTokenExchangeValidation2026!" }
        };
        _configuration = new ConfigurationBuilder().AddInMemoryCollection(configValues).Build();
        _tokenExchangeService = new TokenExchangeService(_permissionStore, _configuration);
    }

    [Fact]
    public async Task ExchangeTokenAsync_ValidScenarioB_MintsDownScopedTokenWithActorClaim()
    {
        // User posts a comment; Comment Service requests OBO token for Notification API
        var userSubjectToken = _tokenExchangeService.CreateSubjectToken(
            userId: "usr_auditor_01",
            firmId: "firm_caseware",
            userType: "firm_staff",
            scopes: new[] { "comments:create", "documents:read", "notifications:write" });

        var request = new TokenExchangeRequest
        {
            GrantType = SecurityConstants.GrantTypes.TokenExchange,
            SubjectToken = userSubjectToken,
            SubjectTokenType = SecurityConstants.TokenTypes.AccessToken,
            Audience = "https://api.caseware.com/notifications",
            Scope = "notifications:write"
        };

        var callerPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(SecurityConstants.Claims.ClientId, "service_collaborate_comments")
        }));

        var result = await _tokenExchangeService.ExchangeTokenAsync(request, callerPrincipal);

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Response);
        Assert.False(string.IsNullOrWhiteSpace(result.Response.AccessToken));
        Assert.Equal("notifications:write", result.Response.Scope);

        // Verify minted JWT claims and RFC 8693 actor attribution
        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(result.Response.AccessToken);

        Assert.Equal("usr_auditor_01", jwt.Subject);
        Assert.Equal("https://api.caseware.com/notifications", jwt.Audiences.First());
        Assert.Equal("firm_caseware", jwt.Claims.First(c => c.Type == SecurityConstants.Claims.FirmId).Value);

        var actorClaim = jwt.Claims.FirstOrDefault(c => c.Type == SecurityConstants.Claims.Actor);
        Assert.NotNull(actorClaim);
        Assert.Contains("service_collaborate_comments", actorClaim.Value);
    }

    [Fact]
    public async Task ExchangeTokenAsync_ConfusedDeputyAttack_RejectsUnauthorizedAudience()
    {
        // Comment service attempts to exchange token for Financial Data API without permission
        var userSubjectToken = _tokenExchangeService.CreateSubjectToken(
            userId: "usr_auditor_01",
            firmId: "firm_caseware",
            userType: "firm_staff",
            scopes: new[] { "financial:read", "notifications:write" });

        var request = new TokenExchangeRequest
        {
            GrantType = SecurityConstants.GrantTypes.TokenExchange,
            SubjectToken = userSubjectToken,
            SubjectTokenType = SecurityConstants.TokenTypes.AccessToken,
            Audience = "https://api.caseware.com/financial-data",
            Scope = "financial:read"
        };

        var callerPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(SecurityConstants.Claims.ClientId, "service_collaborate_comments")
        }));

        var result = await _tokenExchangeService.ExchangeTokenAsync(request, callerPrincipal);

        Assert.False(result.IsSuccess);
        Assert.NotNull(result.Error);
        Assert.Equal(SecurityConstants.Errors.UnauthorizedClient, result.Error.Error);
        Assert.Contains("not permitted to request tokens for audience", result.Error.ErrorDescription);
    }

    [Fact]
    public async Task ExchangeTokenAsync_ScopeEscalation_RejectsWhenScopeExceedsAllowedEntitlements()
    {
        // User has only documents:read, caller requests documents:write
        var userSubjectToken = _tokenExchangeService.CreateSubjectToken(
            userId: "usr_client_external",
            firmId: "firm_external_audit",
            userType: "external_client",
            scopes: new[] { "documents:read" });

        var request = new TokenExchangeRequest
        {
            GrantType = SecurityConstants.GrantTypes.TokenExchange,
            SubjectToken = userSubjectToken,
            SubjectTokenType = SecurityConstants.TokenTypes.AccessToken,
            Audience = "https://api.caseware.com/collaborate",
            Scope = "documents:write"
        };

        var callerPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(SecurityConstants.Claims.ClientId, "client_firm_integration")
        }));

        var result = await _tokenExchangeService.ExchangeTokenAsync(request, callerPrincipal);

        Assert.False(result.IsSuccess);
        Assert.NotNull(result.Error);
        Assert.Equal(SecurityConstants.Errors.UnauthorizedClient, result.Error.Error);
    }

    [Fact]
    public async Task ExchangeTokenAsync_RevokedUser_FailsImmediately()
    {
        _permissionStore.RevokeUser("usr_auditor_01", "firm_caseware");

        var userSubjectToken = _tokenExchangeService.CreateSubjectToken(
            userId: "usr_auditor_01",
            firmId: "firm_caseware",
            userType: "firm_staff",
            scopes: new[] { "notifications:write" });

        var request = new TokenExchangeRequest
        {
            GrantType = SecurityConstants.GrantTypes.TokenExchange,
            SubjectToken = userSubjectToken,
            SubjectTokenType = SecurityConstants.TokenTypes.AccessToken,
            Audience = "https://api.caseware.com/notifications",
            Scope = "notifications:write"
        };

        var callerPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(SecurityConstants.Claims.ClientId, "service_collaborate_comments")
        }));

        var result = await _tokenExchangeService.ExchangeTokenAsync(request, callerPrincipal);

        Assert.False(result.IsSuccess);
        Assert.NotNull(result.Error);
        Assert.Contains("deactivated/revoked", result.Error.ErrorDescription);
    }

    [Fact]
    public async Task ExchangeTokenAsync_ValidScenarioA_ExternalClientToCollaborate_MintsScopedToken()
    {
        // External automated integration calling Collaborate on behalf of an employee
        var userSubjectToken = _tokenExchangeService.CreateSubjectToken(
            userId: "usr_client_external",
            firmId: "firm_external_audit",
            userType: "external_client",
            scopes: new[] { "engagements:read", "documents:read" });

        var request = new TokenExchangeRequest
        {
            GrantType = SecurityConstants.GrantTypes.TokenExchange,
            SubjectToken = userSubjectToken,
            SubjectTokenType = SecurityConstants.TokenTypes.AccessToken,
            Audience = "https://api.caseware.com/collaborate",
            Scope = "engagements:read"
        };

        var callerPrincipal = new ClaimsPrincipal(new ClaimsIdentity(new[]
        {
            new Claim(SecurityConstants.Claims.ClientId, "client_firm_integration")
        }));

        var result = await _tokenExchangeService.ExchangeTokenAsync(request, callerPrincipal);

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Response);
        Assert.Equal("engagements:read", result.Response.Scope);

        var handler = new JwtSecurityTokenHandler();
        var jwt = handler.ReadJwtToken(result.Response.AccessToken);

        Assert.Equal("usr_client_external", jwt.Subject);
        Assert.Equal("firm_external_audit", jwt.Claims.First(c => c.Type == SecurityConstants.Claims.FirmId).Value);

        var actorClaim = jwt.Claims.FirstOrDefault(c => c.Type == SecurityConstants.Claims.Actor);
        Assert.NotNull(actorClaim);
        Assert.Contains("client_firm_integration", actorClaim.Value);
    }
}

