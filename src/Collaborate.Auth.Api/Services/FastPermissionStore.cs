using System.Collections.Concurrent;
using Collaborate.Auth.Api.Models;

namespace Collaborate.Auth.Api.Services;

/// <summary>
/// High-performance, in-memory implementation of the Data Abstraction Layer (IPermissionStore)
/// providing thread-safe caching and permission evaluation for delegation and token exchange.
/// </summary>
public sealed class FastPermissionStore : IPermissionStore
{
    private readonly ConcurrentDictionary<string, CollaborateUser> _users = new();
    private readonly ConcurrentDictionary<string, ClientApplication> _clients = new();

    public FastPermissionStore()
    {
        SeedDefaultData();
    }

    public Task<CollaborateUser?> GetUserAsync(string userId, string firmId, CancellationToken cancellationToken = default)
    {
        var key = $"{firmId}:{userId}";
        _users.TryGetValue(key, out var user);
        return Task.FromResult(user);
    }

    public Task<ClientApplication?> GetClientAppAsync(string clientId, CancellationToken cancellationToken = default)
    {
        _clients.TryGetValue(clientId, out var client);
        return Task.FromResult(client);
    }

    public Task<DelegationDecision> EvaluateDelegationAsync(
        string userId,
        string firmId,
        string callingClientId,
        string targetAudience,
        IEnumerable<string>? requestedScopes,
        CancellationToken cancellationToken = default)
    {
        var userKey = $"{firmId}:{userId}";
        if (!_users.TryGetValue(userKey, out var user) || !user.IsActive)
        {
            return Task.FromResult(new DelegationDecision(
                IsAllowed: false,
                FailureReason: "User does not exist or has been deactivated/revoked.",
                EffectiveScopes: new HashSet<string>()));
        }

        if (!_clients.TryGetValue(callingClientId, out var client) || !client.CanImpersonate)
        {
            return Task.FromResult(new DelegationDecision(
                IsAllowed: false,
                FailureReason: $"Client application '{callingClientId}' is not authorized to perform on-behalf-of delegation.",
                EffectiveScopes: new HashSet<string>()));
        }

        // Prevent confused deputy: ensure caller is authorized to target this downstream audience
        if (!client.AllowedAudiences.Contains(targetAudience) && !client.AllowedAudiences.Contains("*"))
        {
            return Task.FromResult(new DelegationDecision(
                IsAllowed: false,
                FailureReason: $"Client application '{callingClientId}' is not permitted to request tokens for audience '{targetAudience}'.",
                EffectiveScopes: new HashSet<string>()));
        }

        // Intersect user permissions with caller delegation allowances and optional requested scope
        var requestedSet = requestedScopes != null && requestedScopes.Any()
            ? new HashSet<string>(requestedScopes, StringComparer.OrdinalIgnoreCase)
            : null;

        var availableScopes = user.AllowedScopes
            .Intersect(client.AllowedDelegationScopes, StringComparer.OrdinalIgnoreCase)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        var effectiveScopes = requestedSet != null
            ? availableScopes.Intersect(requestedSet, StringComparer.OrdinalIgnoreCase).ToHashSet(StringComparer.OrdinalIgnoreCase)
            : availableScopes;

        if (effectiveScopes.Count == 0)
        {
            return Task.FromResult(new DelegationDecision(
                IsAllowed: false,
                FailureReason: "No authorized overlapping scopes between user permissions and caller delegation entitlements.",
                EffectiveScopes: new HashSet<string>()));
        }

        if (requestedSet != null && !requestedSet.IsSubsetOf(availableScopes))
        {
            return Task.FromResult(new DelegationDecision(
                IsAllowed: false,
                FailureReason: "Requested scopes exceed the allowed delegation entitlements for this user and client application.",
                EffectiveScopes: new HashSet<string>()));
        }

        return Task.FromResult(new DelegationDecision(
            IsAllowed: true,
            FailureReason: null,
            EffectiveScopes: effectiveScopes));
    }

    public void UpsertUser(CollaborateUser user)
    {
        _users[$"{user.FirmId}:{user.UserId}"] = user;
    }

    public void UpsertClientApp(ClientApplication client)
    {
        _clients[client.ClientId] = client;
    }

    public void RevokeUser(string userId, string firmId)
    {
        var key = $"{firmId}:{userId}";
        if (_users.TryGetValue(key, out var user))
        {
            _users[key] = user with { IsActive = false };
        }
    }

    private void SeedDefaultData()
    {
        // Default Firm User (Staff)
        UpsertUser(new CollaborateUser(
            UserId: "usr_auditor_01",
            FirmId: "firm_caseware",
            UserType: "firm_staff",
            AllowedScopes: new HashSet<string> { "documents:read", "documents:write", "comments:read", "comments:create", "notifications:write" },
            IsActive: true));

        // Default External Client User
        UpsertUser(new CollaborateUser(
            UserId: "usr_client_external",
            FirmId: "firm_external_audit",
            UserType: "external_client",
            AllowedScopes: new HashSet<string> { "documents:read", "comments:read", "engagements:read" },
            IsActive: true));

        // Service Caller: Collaborate Comments Service
        UpsertClientApp(new ClientApplication(
            ClientId: "service_collaborate_comments",
            ClientType: "internal_service",
            AllowedAudiences: new HashSet<string> { "https://api.caseware.com/notifications", "https://api.caseware.com/documents" },
            AllowedDelegationScopes: new HashSet<string> { "notifications:write", "documents:read", "comments:read" },
            CanImpersonate: true));

        // External Calling Client: Firm Automated System
        UpsertClientApp(new ClientApplication(
            ClientId: "client_firm_integration",
            ClientType: "external_app",
            AllowedAudiences: new HashSet<string> { "https://api.caseware.com/collaborate" },
            AllowedDelegationScopes: new HashSet<string> { "engagements:read", "documents:read" },
            CanImpersonate: true));
    }
}

