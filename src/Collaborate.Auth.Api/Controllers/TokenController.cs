using Collaborate.Auth.Api.Models;
using Collaborate.Auth.Api.Services;
using Microsoft.AspNetCore.Mvc;

namespace Collaborate.Auth.Api.Controllers;

[ApiController]
[Route("oauth")]
public sealed class TokenController : ControllerBase
{
    private readonly ITokenExchangeService _tokenExchangeService;
    private readonly ILogger<TokenController> _logger;

    public TokenController(ITokenExchangeService tokenExchangeService, ILogger<TokenController> logger)
    {
        _tokenExchangeService = tokenExchangeService;
        _logger = logger;
    }

    /// <summary>
    /// OAuth 2.0 Token Endpoint supporting RFC 8693 Token Exchange.
    /// Accepts both application/x-www-form-urlencoded (standard) and application/json.
    /// </summary>
    [HttpPost("token")]
    [Consumes("application/x-www-form-urlencoded", "application/json")]
    [Produces("application/json")]
    public async Task<IActionResult> Token([FromForm] TokenExchangeRequest formRequest, CancellationToken cancellationToken)
    {
        var request = formRequest;

        // If body was sent as JSON instead of form-data
        if (string.IsNullOrWhiteSpace(request.GrantType) && HttpContext.Request.HasJsonContentType())
        {
            var jsonRequest = await HttpContext.Request.ReadFromJsonAsync<TokenExchangeRequest>(cancellationToken: cancellationToken);
            if (jsonRequest != null)
            {
                request = jsonRequest;
            }
        }

        _logger.LogInformation(
            "Received token exchange request for grant_type: {GrantType}, audience: {Audience}, requested_scope: {Scope}",
            request.GrantType,
            request.Audience,
            request.Scope);

        var result = await _tokenExchangeService.ExchangeTokenAsync(request, User, cancellationToken);

        if (!result.IsSuccess)
        {
            _logger.LogWarning(
                "Token exchange rejected with error: {Error}, description: {Description}",
                result.Error?.Error,
                result.Error?.ErrorDescription);

            var statusCode = result.Error?.Error switch
            {
                SecurityConstants.Errors.InvalidRequest => StatusCodes.Status400BadRequest,
                SecurityConstants.Errors.InvalidGrant => StatusCodes.Status400BadRequest,
                SecurityConstants.Errors.UnsupportedGrantType => StatusCodes.Status400BadRequest,
                SecurityConstants.Errors.UnauthorizedClient => StatusCodes.Status403Forbidden,
                SecurityConstants.Errors.InvalidTarget => StatusCodes.Status400BadRequest,
                _ => StatusCodes.Status400BadRequest
            };

            return StatusCode(statusCode, result.Error);
        }

        _logger.LogInformation("Token exchange successfully issued token for audience: {Audience}", request.Audience);
        return Ok(result.Response);
    }
}

