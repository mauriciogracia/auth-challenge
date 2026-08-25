using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Collaborate.Auth.Api.Models;
using Microsoft.IdentityModel.Tokens;

namespace Collaborate.Auth.Api.Services;

/// <summary>
/// Implements RFC 8693 Token Exchange for service-to-service and client-to-service delegation.
/// Mints downstream tokens with separated 'sub' (User), 'act' (Calling service), and 'aud' (Target resource).
/// </summary>
public sealed class TokenExchangeService : ITokenExchangeService
{
    private readonly IPermissionStore _permissionStore;
    private readonly IConfiguration _configuration;
    private readonly JwtSecurityTokenHandler _tokenHandler;
    private readonly SymmetricSecurityKey _signingKey;
    private readonly string _issuer;

    public TokenExchangeService(IPermissionStore permissionStore, IConfiguration configuration)
    {
        _permissionStore = permissionStore;
        _configuration = configuration;
        _tokenHandler = new JwtSecurityTokenHandler();

        var secret = _configuration["Auth:SigningKey"] ?? "CollaborateSuperSecretKeyForTokenExchangeValidation2026!";
        _signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
        _issuer = _configuration["Auth:Issuer"] ?? "https://auth.collaborate.caseware.com";
    }

    public async Task<TokenExchangeResult> ExchangeTokenAsync(
        TokenExchangeRequest request,
        ClaimsPrincipal? callerPrincipal,
        CancellationToken cancellationToken = default)
    {
        // 1. Validate Grant Type (RFC 8693 Section 2.1)
        if (!string.Equals(request.GrantType, SecurityConstants.GrantTypes.TokenExchange, StringComparison.Ordinal))
        {
            return new TokenExchangeResult(
                IsSuccess: false,
                Response: null,
                Error: new TokenExchangeErrorResponse
                {
                    Error = SecurityConstants.Errors.UnsupportedGrantType,
                    ErrorDescription = $"grant_type must be '{SecurityConstants.GrantTypes.TokenExchange}'."
                });
        }

        // 2. Validate Subject Token
        if (string.IsNullOrWhiteSpace(request.SubjectToken))
        {
            return new TokenExchangeResult(
                IsSuccess: false,
                Response: null,
                Error: new TokenExchangeErrorResponse
                {
                    Error = SecurityConstants.Errors.InvalidRequest,
                    ErrorDescription = "subject_token is required."
                });
        }

        // 3. Validate Target Audience
        if (string.IsNullOrWhiteSpace(request.Audience))
        {
            return new TokenExchangeResult(
                IsSuccess: false,
                Response: null,
                Error: new TokenExchangeErrorResponse
                {
                    Error = SecurityConstants.Errors.InvalidTarget,
                    ErrorDescription = "audience parameter is required to identify downstream target service."
                });
        }

        // 4. Parse and Validate incoming Subject Token (using standard ASP.NET Core token validation)
        ClaimsPrincipal subjectPrincipal;
        try
        {
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = _issuer,
                ValidateAudience = false, // Subject token might have a different audience than target
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = _signingKey,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(30)
            };

            subjectPrincipal = _tokenHandler.ValidateToken(request.SubjectToken, validationParameters, out _);
        }
        catch (Exception ex)
        {
            return new TokenExchangeResult(
                IsSuccess: false,
                Response: null,
                Error: new TokenExchangeErrorResponse
                {
                    Error = SecurityConstants.Errors.InvalidGrant,
                    ErrorDescription = $"subject_token is invalid or expired: {ex.Message}"
                });
        }

        // 5. Extract Subject Claims
        var userId = subjectPrincipal.FindFirst(SecurityConstants.Claims.Subject)?.Value
                     ?? subjectPrincipal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var firmId = subjectPrincipal.FindFirst(SecurityConstants.Claims.FirmId)?.Value
                     ?? subjectPrincipal.FindFirst(SecurityConstants.Claims.TenantId)?.Value
                     ?? "firm_caseware";
        var userType = subjectPrincipal.FindFirst(SecurityConstants.Claims.UserType)?.Value ?? "firm_staff";

        if (string.IsNullOrWhiteSpace(userId))
        {
            return new TokenExchangeResult(
                IsSuccess: false,
                Response: null,
                Error: new TokenExchangeErrorResponse
                {
                    Error = SecurityConstants.Errors.InvalidGrant,
                    ErrorDescription = "subject_token does not contain a valid 'sub' claim."
                });
        }

        // 6. Determine Calling Client ID
        var callingClientId = callerPrincipal?.FindFirst(SecurityConstants.Claims.ClientId)?.Value
                              ?? callerPrincipal?.FindFirst(ClaimTypes.NameIdentifier)?.Value
                              ?? request.ActorToken // Fallback for client credentials / actor token
                              ?? "service_collaborate_comments";

        // 7. Parse requested scopes if provided
        var requestedScopes = !string.IsNullOrWhiteSpace(request.Scope)
            ? request.Scope.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            : null;

        // 8. Evaluate Delegation against Data Abstraction Layer (IPermissionStore)
        var delegation = await _permissionStore.EvaluateDelegationAsync(
            userId: userId,
            firmId: firmId,
            callingClientId: callingClientId,
            targetAudience: request.Audience,
            requestedScopes: requestedScopes,
            cancellationToken: cancellationToken);

        if (!delegation.IsAllowed)
        {
            return new TokenExchangeResult(
                IsSuccess: false,
                Response: null,
                Error: new TokenExchangeErrorResponse
                {
                    Error = SecurityConstants.Errors.UnauthorizedClient,
                    ErrorDescription = delegation.FailureReason ?? "Delegation authorization failed."
                });
        }

        // 9. Mint Down-Scoped Downstream JWT with Actor Claim
        var downstreamJwt = MintDownstreamToken(
            userId: userId,
            firmId: firmId,
            userType: userType,
            callingClientId: callingClientId,
            targetAudience: request.Audience,
            effectiveScopes: delegation.EffectiveScopes);

        return new TokenExchangeResult(
            IsSuccess: true,
            Response: new TokenExchangeResponse
            {
                AccessToken = downstreamJwt,
                IssuedTokenType = SecurityConstants.TokenTypes.AccessToken,
                TokenType = "Bearer",
                ExpiresIn = 3600,
                Scope = string.Join(" ", delegation.EffectiveScopes)
            },
            Error: null);
    }

    private string MintDownstreamToken(
        string userId,
        string firmId,
        string userType,
        string callingClientId,
        string targetAudience,
        IEnumerable<string> effectiveScopes)
    {
        var claims = new List<Claim>
        {
            new(SecurityConstants.Claims.Subject, userId),
            new(SecurityConstants.Claims.FirmId, firmId),
            new(SecurityConstants.Claims.TenantId, firmId),
            new(SecurityConstants.Claims.UserType, userType),
            new(SecurityConstants.Claims.JwtId, Guid.NewGuid().ToString("N")),
            // RFC 8693 Actor Claim format: act: { "sub": "calling_client_id" }
            new(SecurityConstants.Claims.Actor, JsonSerializer.Serialize(new { sub = callingClientId }), JsonClaimValueTypes.Json)
        };

        // Add scoped permissions
        foreach (var scope in effectiveScopes)
        {
            claims.Add(new Claim(SecurityConstants.Claims.Scope, scope));
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            Audience = targetAudience,
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256Signature)
        };

        var token = _tokenHandler.CreateToken(tokenDescriptor);
        return _tokenHandler.WriteToken(token);
    }

    /// <summary>
    /// Helper method to create initial valid subject tokens (useful for testing and initial client auth).
    /// </summary>
    public string CreateSubjectToken(string userId, string firmId, string userType, IEnumerable<string> scopes)
    {
        var claims = new List<Claim>
        {
            new(SecurityConstants.Claims.Subject, userId),
            new(SecurityConstants.Claims.FirmId, firmId),
            new(SecurityConstants.Claims.TenantId, firmId),
            new(SecurityConstants.Claims.UserType, userType),
            new(SecurityConstants.Claims.JwtId, Guid.NewGuid().ToString("N"))
        };

        foreach (var scope in scopes)
        {
            claims.Add(new Claim(SecurityConstants.Claims.Scope, scope));
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            Audience = "https://api.caseware.com/collaborate",
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddHours(2),
            SigningCredentials = new SigningCredentials(_signingKey, SecurityAlgorithms.HmacSha256Signature)
        };

        var token = _tokenHandler.CreateToken(tokenDescriptor);
        return _tokenHandler.WriteToken(token);
    }
}

