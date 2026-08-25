using System.Text.Json.Serialization;

namespace Collaborate.Auth.Api.Models;

/// <summary>
/// Represents standard RFC 8693 OAuth 2.0 Token Exchange successful response.
/// </summary>
public sealed class TokenExchangeResponse
{
    [JsonPropertyName("access_token")]
    public string AccessToken { get; init; } = string.Empty;

    [JsonPropertyName("issued_token_type")]
    public string IssuedTokenType { get; init; } = SecurityConstants.TokenTypes.AccessToken;

    [JsonPropertyName("token_type")]
    public string TokenType { get; init; } = "Bearer";

    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; init; } = 3600;

    [JsonPropertyName("scope")]
    public string? Scope { get; init; }
}

/// <summary>
/// Represents standard RFC 6749 / RFC 8693 OAuth 2.0 error response.
/// </summary>
public sealed class TokenExchangeErrorResponse
{
    [JsonPropertyName("error")]
    public string Error { get; init; } = string.Empty;

    [JsonPropertyName("error_description")]
    public string? ErrorDescription { get; init; }
}

