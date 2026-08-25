using System.Security.Claims;
using Collaborate.Auth.Api.Models;

namespace Collaborate.Auth.Api.Services;

/// <summary>
/// Service implementing OAuth 2.0 Token Exchange (RFC 8693) for On-Behalf-Of delegation.
/// </summary>
public interface ITokenExchangeService
{
    /// <summary>
    /// Validates an incoming token exchange request, evaluates delegation permissions,
    /// and mints a scoped downstream JWT preserving subject identity and actor claims.
    /// </summary>
    Task<TokenExchangeResult> ExchangeTokenAsync(
        TokenExchangeRequest request,
        ClaimsPrincipal? callerPrincipal,
        CancellationToken cancellationToken = default);
}

public sealed record TokenExchangeResult(
    bool IsSuccess,
    TokenExchangeResponse? Response,
    TokenExchangeErrorResponse? Error);

