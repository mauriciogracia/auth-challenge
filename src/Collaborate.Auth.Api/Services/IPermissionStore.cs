using Collaborate.Auth.Api.Models;

namespace Collaborate.Auth.Api.Services;

/// <summary>
/// Data Abstraction Layer for querying users, client applications,
/// and evaluating delegation decisions across multi-tier caching and backing storage.
/// </summary>
public interface IPermissionStore
{
    /// <summary>
    /// Retrieves the user record and their active permissions.
    /// </summary>
    Task<CollaborateUser?> GetUserAsync(string userId, string firmId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the registered client application configuration.
    /// </summary>
    Task<ClientApplication?> GetClientAppAsync(string clientId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Evaluates delegation rules and computes the effective intersection of scopes:
    /// Effective Scope = User Permissions ∩ Client Delegation Scopes ∩ Requested Scope
    /// </summary>
    Task<DelegationDecision> EvaluateDelegationAsync(
        string userId,
        string firmId,
        string callingClientId,
        string targetAudience,
        IEnumerable<string>? requestedScopes,
        CancellationToken cancellationToken = default);
}

