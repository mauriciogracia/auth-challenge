using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Mvc;

namespace Collaborate.Auth.Api.Models;

/// <summary>
/// Represents standard RFC 8693 OAuth 2.0 Token Exchange request parameters.
/// </summary>
public sealed class TokenExchangeRequest
{
    [FromForm(Name = "grant_type")]
    [JsonPropertyName("grant_type")]
    public string GrantType { get; set; } = string.Empty;

    [FromForm(Name = "subject_token")]
    [JsonPropertyName("subject_token")]
    public string SubjectToken { get; set; } = string.Empty;

    [FromForm(Name = "subject_token_type")]
    [JsonPropertyName("subject_token_type")]
    public string SubjectTokenType { get; set; } = string.Empty;

    [FromForm(Name = "actor_token")]
    [JsonPropertyName("actor_token")]
    public string? ActorToken { get; set; }

    [FromForm(Name = "actor_token_type")]
    [JsonPropertyName("actor_token_type")]
    public string? ActorTokenType { get; set; }

    [FromForm(Name = "audience")]
    [JsonPropertyName("audience")]
    public string? Audience { get; set; }

    [FromForm(Name = "scope")]
    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    [FromForm(Name = "resource")]
    [JsonPropertyName("resource")]
    public string? Resource { get; set; }
}

