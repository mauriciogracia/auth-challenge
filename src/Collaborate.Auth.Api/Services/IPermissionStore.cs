using Collaborate.Auth.Api.Models;

namespace Collaborate.Auth.Api.Services;

/// <summary>
/// Data Abstraction Layer for querying user permissions, client delegation entitlements,
/// and evaluating effective scopes across multi-tier caching and backing storage.
/// </summary>
public interface IPermissionStore
{
    /// <summary>
    /// Retrieves the current subject context (roles, scopes, active status) for a user.
    /// </summary>
    Task<UserSubjectContext?> GetUserSubjectAsync(string userId, string firmId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Retrieves the registered calling client's delegation permissions and allowed audiences.
    /// </summary>
    Task<CallingClientContext?> GetCallingClientAsync(string clientId, CancellationToken cancellationToken = default);

    /// <summary>
    /// Evaluates delegation entitlements and computes the effective intersection of scopes:
    /// Effective Scope = User Permissions ∩ Caller Delegation Entitlements ∩ Requested Scope
    /// </summary>
    Task<DelegationEvaluationResult> EvaluateDelegationAsync(
        string userId,
        string firmId,
        string callingClientId,
        string targetAudience,
        IEnumerable<string>? requestedScopes,
        CancellationToken cancellationToken = default);
}

