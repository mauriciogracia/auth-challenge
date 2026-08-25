# Caseware Collaborate — Identity & Authorization Solution

This repository contains the architecture specification and targeted implementation for the **Senior Developer Take-Home Exercise (Collaborate)**.

---

## 📁 Repository Structure

```
├── docs/
│   ├── part-1-specs.md                                         # Part 1: Full Architecture & Design Specification (5 sections)
│   ├── notes.md                                                # Engineering decision log & business context
│   ├── tech-specs.md                                           # Engineering standards (SOLID, ACID, Polly Resilience)
│   ├── Senior Developer, Collaborate - Take-Home Test.md       # Original exercise prompt (Markdown)
│   └── Senior Developer, Collaborate - Take-Home Test.pdf      # Original exercise prompt (PDF)
├── src/
│   └── Collaborate.Auth.Api/                                   # ASP.NET Core 8 Web API (Part 2 Implementation)
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
│       │   ├── FastPermissionStore.cs                          # Thread-safe store with policy evaluation
│       │   ├── ITokenExchangeService.cs                        # Token exchange contract
│       │   └── TokenExchangeService.cs                         # RFC 8693 OBO Token Exchange engine
│       ├── Program.cs                                          # DI container, JWT authentication & Swagger setup
│       ├── Properties/
│       │   └── launchSettings.json                             # Root Swagger UI launch configuration
│       └── appsettings.json
├── tests/
│   └── Collaborate.Auth.Tests/                                 # Unit & Integration Tests (xUnit + WebApplicationFactory)
│       ├── TokenExchangeServiceTests.cs                        # Unit tests for OBO delegation, scope math, revocation
│       └── TokenExchangeIntegrationTests.cs                    # E2E integration tests against HTTP pipeline
└── Collaborate.Auth.sln
```

---

## 🚀 Part 1: Architecture & Design Summary

The full architecture specification is documented in <a href="docs/part-1-specs.md" target="_blank" rel="noopener noreferrer">docs/part-1-specs.md</a>.

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
- <a href="https://dotnet.microsoft.com/download/dotnet/8.0" target="_blank" rel="noopener noreferrer">.NET 8.0 SDK</a>

### 1. Build the Solution
```bash
dotnet build
```

### 2. Run API & Access Swagger UI
```bash
dotnet run --project src/Collaborate.Auth.Api
```
When started, the API automatically serves the **interactive Swagger UI as the root landing page**:
- **HTTP**: <a href="http://localhost:5032/" target="_blank" rel="noopener noreferrer">http://localhost:5032/</a>
- **HTTPS**: <a href="https://localhost:7020/" target="_blank" rel="noopener noreferrer">https://localhost:7020/</a>
- **Health Check**: <a href="http://localhost:5032/health" target="_blank" rel="noopener noreferrer">http://localhost:5032/health</a>

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

## 📌 Architecture & Documentation Index

- <a href="docs/part-1-specs.md" target="_blank" rel="noopener noreferrer"><strong>docs/part-1-specs.md</strong></a>: Full Architecture & Design Specification covering the 5 prompt areas (High-Level Architecture, Implementation Plan, Testing Strategy, Evaluation & Observability, Failure Modes & Tradeoffs).
- <a href="docs/notes.md" target="_blank" rel="noopener noreferrer"><strong>docs/notes.md</strong></a>: Engineering Decision Log explaining the business context of Collaborate and the technical "why" behind each architectural decision.
- <a href="docs/tech-specs.md" target="_blank" rel="noopener noreferrer"><strong>docs/tech-specs.md</strong></a>: Engineering Standards covering SOLID principles, ACID transactional guarantees, Polly circuit breakers, and non-blocking I/O.
- <a href="docs/Senior%20Developer,%20Collaborate%20-%20Take-Home%20Test.md" target="_blank" rel="noopener noreferrer"><strong>docs/Senior Developer, Collaborate - Take-Home Test.md</strong></a>: Original take-home problem description and evaluation guidelines.
