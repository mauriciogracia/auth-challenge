# Caseware Collaborate — Identity & Authorization Solution

This repository contains the architecture specification and targeted implementation for the **Senior Developer Take-Home Exercise (Collaborate)**.

---

## 📁 Repository Structure

```
├── docs/
│   ├── part-1-specs.md                                         # Part 1: Full Architecture & Design Specification (1-3 pages)
│   ├── notes.md                                                # Architecture decisions & notes log
│   └── Senior Developer, Collaborate - Take-Home Test...pdf    # Original exercise prompt
├── src/
│   └── Collaborate.Auth.Api/                                   # ASP.NET Core Web API (Part 2 Implementation)
│       ├── Controllers/
│       │   ├── TokenController.cs                              # POST /oauth/token (RFC 8693 Token Exchange)
│       │   └── DownstreamSamplesController.cs                  # Protected downstream API (Notifications/Docs)
│       ├── Models/
│       │   ├── TokenExchangeRequest.cs                         # RFC 8693 Request schema
│       │   ├── TokenExchangeResponse.cs                        # RFC 8693 Response schema
│       │   ├── EntitlementModels.cs                            # Context & delegation result models
│       │   └── SecurityConstants.cs                            # Standard grant types, token types, claims
│       ├── Services/
│       │   ├── IPermissionStore.cs                             # Data Abstraction Layer (DAL)
│       │   ├── InMemoryPermissionStore.cs                      # Thread-safe in-memory store with policy evaluation
│       │   ├── ITokenExchangeService.cs                        # Token exchange contract
│       │   └── TokenExchangeService.cs                         # RFC 8693 OBO Token Exchange engine
│       ├── Program.cs                                          # DI container & JWT authentication setup
│       └── appsettings.json
├── tests/
│   └── Collaborate.Auth.Tests/                                 # Unit & Integration Tests (xUnit + WebApplicationFactory)
│       ├── TokenExchangeServiceTests.cs                        # Unit tests for OBO delegation, scope math, revocation
│       └── TokenExchangeIntegrationTests.cs                    # E2E integration tests against HTTP pipeline
└── Collaborate.Auth.sln
```

---

## 🚀 Part 1: Architecture & Design Summary

The full architecture specification is documented in [docs/part-1-specs.md](docs/part-1-specs.md).

Key highlights:
- **Authentication & Federation:** Email-first Home Realm Discovery (`/api/v1/auth/discovery`) routing internal staff to Caseware Central IdP and external client users to federated SAML/OIDC IdPs via Auth Code + PKCE.
- **Multi-Tier Caching ($10\text{k}+$ checks/sec):** L1 In-Memory (`IMemoryCache`, 30–60s) $\rightarrow$ L2 Distributed Redis (10–15m) $\rightarrow$ Relational DB source of truth via the `IPermissionStore` Data Abstraction Layer.
- **Sub-Second Revocation (<1s):** Database commit hooks publish to Redis Pub/Sub (`collaborate:events:security-revocation`), triggering instant local L1 cache eviction and SignalR WebSocket session disconnects.
- **On-Behalf-Of (OBO) Delegation:** RFC 8693 Token Exchange separating subject (`sub`), actor (`act`), and audience (`aud`) claims to eliminate the Confused Deputy vulnerability.
- **Observability:** Full Datadog APM distributed tracing with W3C headers and structured JSON audit logging.

---

## 🛠️ Part 2: Targeted Implementation (Option C)

We implemented **Option C: On-Behalf-Of (OBO) Token Exchange Endpoint** using standard ASP.NET Core 8 primitives:

### Key Features:
1. **RFC 8693 Compliance:** `POST /oauth/token` handling `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`.
2. **Actor Claim Attribution:** Minted downstream tokens clearly decouple the human user (`sub`) from the calling service (`act: { "sub": "service_collaborate_comments" }`).
3. **Audience Lockdown (`aud`):** Each exchanged token is strictly bound to its target downstream service (e.g., `https://api.caseware.com/notifications`), preventing token reuse against other APIs.
4. **Scope Narrowing & Math:** Automatically intersects user permissions, caller delegation entitlements, and requested scopes:
   $$\text{Effective Scope} = \text{User Permissions} \cap \text{Caller Delegation} \cap \text{Requested Scope}$$
5. **Instant Revocation Handling:** Deactivated/revoked users fail token exchange immediately.

---

## 🧪 Building & Running Tests

### Prerequisites
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

### Build Solution
```bash
dotnet build
```

### Run Test Suite
```bash
dotnet test
```

### Test Coverage Highlights:
- ✅ **Scenario (a):** External automated integration exchanging token to call Collaborate API on behalf of an employee.
- ✅ **Scenario (b):** Internal Comments Service exchanging token to call Notification API on behalf of a user who posted a comment.
- ✅ **Confused Deputy Mitigation:** Rejection of token exchange when caller attempts to target an unauthorized downstream audience.
- ✅ **Privilege Escalation Protection:** Rejection when caller requests scopes exceeding allowed entitlements.
- ✅ **Instant Revocation:** Immediate failure of token exchange for deactivated users.
- ✅ **End-to-End Pipeline:** Full `WebApplicationFactory` integration testing verifying downstream audience validation and audit logging.

