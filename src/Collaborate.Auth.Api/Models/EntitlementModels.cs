namespace Collaborate.Auth.Api.Models;

/// <summary>
/// Represents an authenticated Collaborate user and their active permissions.
/// </summary>
public sealed record CollaborateUser(
    string UserId,
    string FirmId,
    string UserType,
    IReadOnlySet<string> AllowedScopes,
    bool IsActive = true);

/// <summary>
/// Represents a registered internal service or external client application.
/// </summary>
public sealed record ClientApplication(
    string ClientId,
    string ClientType,
    IReadOnlySet<string> AllowedAudiences,
    IReadOnlySet<string> AllowedDelegationScopes,
    bool CanImpersonate = true);

/// <summary>
/// The evaluated outcome of an on-behalf-of delegation request.
/// </summary>
public sealed record DelegationDecision(
    bool IsAllowed,
    string? FailureReason,
    IReadOnlySet<string> EffectiveScopes);

