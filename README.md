# Caseware Collaborate — Identity & Authorization Solution

This repository contains the architecture specification and targeted implementation for the **Senior Developer Take-Home Exercise (Collaborate)**.

---

## 📁 Repository Structure

```
├── docs/
│   ├── part-1-specs.md                                         # Part 1: Full Architecture & Design Specification (1-3 pages)
│   ├── tech-specs.md                                           # Engineering standards (Single-return, DRY, SOLID, ACID, Resilience)
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
│       │   ├── EntitlementModels.cs                            # CollaborateUser, ClientApplication, DelegationDecision
│       │   └── SecurityConstants.cs                            # Standard grant types, token types, claims
│       ├── Services/
│       │   ├── IPermissionStore.cs                             # Data Abstraction Layer (DAL)
│       │   ├── FastPermissionStore.cs                          # Thread-safe fast store with policy evaluation
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

Implementation of **Option C: On-Behalf-Of (OBO) Token Exchange Endpoint** using standard ASP.NET Core 8 primitives:

### Key Features:
1. **RFC 8693 Compliance:** `POST /oauth/token` handling `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`.
2. **Actor Claim Attribution:** Minted downstream tokens clearly decouple the human user (`sub`) from the calling service (`act: { "sub": "service_collaborate_comments" }`).
3. **Audience Lockdown (`aud`):** Each exchanged token is strictly bound to its target downstream service (e.g., `https://api.caseware.com/notifications`), preventing token reuse against other APIs.
4. **Scope Narrowing & Math:** Automatically intersects user permissions, caller delegation entitlements, and requested scopes:
   $$\text{Effective Scope} = \text{User Permissions} \cap \text{Caller Delegation} \cap \text{Requested Scope}$$
5. **Instant Revocation Handling:** Deactivated/revoked users fail token exchange immediately.

---

## 🧪 Building, Running & Testing

### Prerequisites
- [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

### 1. Build the Solution
```bash
dotnet build
```

### 2. Run API & Access Swagger UI
```bash
dotnet run --project src/Collaborate.Auth.Api
```
When started, the API automatically serves the **interactive Swagger UI as the root landing page**:
- **HTTP**: [http://localhost:5032/](http://localhost:5032/)
- **HTTPS**: [https://localhost:7020/](https://localhost:7020/)
- **Health Check**: [http://localhost:5032/health](http://localhost:5032/health)

#### 🎮 Testing Interactively in Swagger UI:
1. **Exchange a Token (`POST /oauth/token`)**:
   - Send `grant_type`: `urn:ietf:params:oauth:grant-type:token-exchange`
   - Send `subject_token`: Valid user JWT (or test token minted for `usr_auditor_01`)
   - Send `audience`: `https://api.caseware.com/notifications`
   - Send `scope`: `notifications:write`
   - Send `actor_token`: `service_collaborate_comments`
   - Click **Execute** $\rightarrow$ Receive down-scoped downstream JWT with `act` claims.
2. **Authorize Swagger**:
   - Click the **Authorize** 🔓 button at the top right of Swagger UI.
   - Enter `Bearer <downstream_access_token>`.
3. **Call Protected Resource (`POST /api/notifications`)**:
   - Execute with payload `{ "content": "Audit comment posted" }`.
   - Returns `200 OK` showing subject attribution (`usr_auditor_01`) and actor logging (`service_collaborate_comments`).

### 3. Run Automated Test Suite
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

---

## 📌 Architecture & Design Highlights

- **Specification**: [docs/part-1-specs.md](docs/part-1-specs.md) covers the complete 5-section architecture design document.
- **Engineering Standards**: [docs/tech-specs.md](docs/tech-specs.md) covers code construction, SOLID principles, ACID guarantees, and resilience patterns.
- **Decision Notes**: [docs/notes.md](docs/notes.md) contains architectural decisions and trade-offs.

