# Part 1: Architecture & Design Specification

**System:** Caseware Collaborate Identity & Authorization Platform  
**Target Platform:** ASP.NET Core (.NET 8/9), AWS, Redis Cluster  

---

## 1. High-Level Architecture

Collaborate requires a robust, standards-compliant (OAuth2 / OIDC), high-throughput identity and authorization layer that supports multi-tenant firm federation, fine-grained permission enforcement, real-time revocation, and secure on-behalf-of delegation.

```mermaid
graph TD
    subgraph Clients & Consumers
        SPA[Browser / Single Page App]
        ExtClient[External Client System]
        WSClient[Collaborative Editing / WebSocket]
    end

    subgraph Identity & Federation Broker
        AuthSvc[Collaborate Auth Service\nOAuth2 / OIDC Server + Relying Party]
        HRD[Discovery & Realm Routing\n/api/v1/auth/discovery]
    end

    subgraph Upstream IdPs
        CWIdP[Caseware Central IdP\nOIDC Discovery / UserInfo]
        FedIdP[Firm Federated IdP\nSAML 2.0 / OIDC]
    end

    subgraph Caching & Invalidation Layer
        L1[L1 In-Memory Cache\nIMemoryCache 30-60s]
        L2[(L2 Redis Cluster\nDistributed Cache & Pub/Sub)]
    end

    subgraph Core Collaborate Services
        DocSvc[Document Service]
        FinSvc[Financial Data API]
        CommSvc[Comments Service]
        SignalRHub[SignalR / WebSocket Hubs]
    end

    subgraph Downstream & Background Services
        NotifSvc[Notification Service]
    end

    subgraph Data Tier
        DB[(Collaborate Relational DB\nRoles, Policies, ACLs)]
    end

    %% Flows
    SPA -->|1. Auth Code + PKCE| AuthSvc
    AuthSvc -->|Discover Realm| HRD
    HRD -->|Firm Staff| CWIdP
    HRD -->|Client Users| FedIdP
    AuthSvc -->|Issues RS256 JWT| SPA

    SPA -->|Bearer JWT| DocSvc
    SPA -->|Bearer JWT| FinSvc
    SPA -->|Bearer JWT| CommSvc
    WSClient -->|Persistent WSS| SignalRHub

    %% Caching Flows
    DocSvc -->|Check L1| L1
    L1 -.->|Miss: Check L2| L2
    L2 -.->|Miss: Fetch & Compute| DB

    %% Revocation Flow
    DB -->|EF Core Hook / Outbox| L2
    L2 -->|Pub/Sub Revocation Event| DocSvc
    L2 -->|Pub/Sub Revocation Event| SignalRHub
    SignalRHub -->|Disconnect Session / 403| WSClient

    %% Delegation Flows
    ExtClient -->|Token Exchange RFC 8693| AuthSvc
    CommSvc -->|OBO Token Exchange| AuthSvc
    AuthSvc -->|Scoped Down JWT act:comment_svc| NotifSvc
```

---

### 1.1 Authentication & Identity Federation (Login Flow)

To accommodate both internal firm employees and external clients with per-firm federation, Collaborate Auth acts as a **Federation Broker (OIDC Relying Party to upstream IdPs, and OAuth 2.0 Authorization Server to Collaborate clients)**.

1. **User Discovery (Home Realm Discovery - HRD):**
   - The frontend presents an email-first login screen.
   - An unauthenticated discovery endpoint (`GET /api/v1/auth/discovery?email={user@domain.com}`) determines tenant routing:
     - **Firm Staff:** Routed to **Caseware Central IdP** (standard OIDC discovery, token, userinfo).
     - **Federated Enterprise Clients:** Routed to the firm's federated **SAML 2.0 / OIDC IdP** configured for that firm context.
     - **Unfederated External Users:** Handled via standard Collaborate invite / local credential flow.

2. **Authorization Code Flow with PKCE:**
   - Client applications initiate standard **OAuth 2.0 Authorization Code Flow + PKCE** (`code_challenge` and `code_challenge_method=S256`) against Collaborate's `/authorize` endpoint.
   - Collaborate preserves client state and PKCE parameters, acting as a gateway and redirecting the browser to the selected upstream IdP.

3. **Assertion Ingestion & Token Minting:**
   - The upstream IdP validates credentials/MFA and redirects to Collaborate’s callback handler (`/auth/callback/{provider}`).
   - Collaborate verifies cryptographic signatures, extracts claims (`email`, `upn`, `name_id`), and maps the subject to the internal Collaborate user record and firm membership.
   - Collaborate completes the PKCE exchange and mints a standard **RS256 signed JWT Access Token** containing standardized claims:
     - `sub`: Collaborate internal user ID.
     - `tenant_id` / `firm_id`: Active firm context.
     - `user_type`: `firm_staff` or `external_client`.
     - `jti` / `sid`: Unique token and session identifiers for rapid revocation tracking.

---

### 1.2 Fine-Grained Authorization & Multi-Tier Caching (10k+ req/sec)

Downstream resource APIs (Document Service, Financial Data API, Comments Service) do not communicate directly with the relational database for each authorization check. A multi-tier caching strategy guarantees sub-millisecond evaluation at scale.

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Client
    participant API as Downstream Resource API
    participant L1 as L1 In-Memory (IMemoryCache)
    participant L2 as L2 Distributed Cache (Redis)
    participant DB as Relational DB (Source of Truth)

    User->>API: HTTP Request + Bearer JWT
    API->>API: Validate JWT (Signature, Expiry, Issuer, Audience)
    API->>L1: Check Cached Permission (user_id, resource_id, action)
    alt L1 Hit (0ms)
        L1-->>API: Return Cached Decision (ALLOW / DENY)
    else L1 Miss
        API->>L2: GET firm:{fid}:res:{rid}:user:{uid}:acl
        alt L2 Hit (<1ms)
            L2-->>API: Return Cached Decision
            API->>L1: Populate L1 (TTL: 30-60s)
        else L2 Miss
            API->>DB: Query Workspace Roles, Firm Policy, Resource ACLs
            DB-->>API: Raw Entitlements
            API->>API: Compute Effective Permission: (Policy ∧ Role ∨ ACL)
            API->>L2: SET key + TTL (10-15m)
            API->>L1: SET key + TTL (30-60s)
        end
    end
    API-->>User: 200 OK (or 403 Forbidden)
```

- **L1 In-Memory Cache (Per-Instance):** Utilizes ASP.NET Core `IMemoryCache` with a 30–60 second sliding TTL. Serves hot-path requests with zero network latency.
- **L2 Distributed Cache (Shared Redis Cluster):** Clustered Redis caching structured permission keys (TTL 10–15 minutes):
  - Workspace Role: `firm:{firm_id}:ws:{workspace_id}:user:{user_id}:role`
  - Resource Overrides: `firm:{firm_id}:res:{resource_id}:user:{user_id}:acl`
- **Evaluation Logic (Hybrid RBAC + ABAC):**
  $$\text{Access Granted} \iff \text{Firm Policy Evaluates TRUE} \land (\text{Workspace Role Entitlement} \lor \text{Resource ACL Override})$$

---

### 1.3 Real-Time Revocation & Long-Lived Session Cutoff (<1s)

When permissions change or users are removed from workspaces, access must be revoked within seconds across both stateless HTTP requests and stateful connections (WebSockets / collaborative editing).

```mermaid
sequenceDiagram
    autonumber
    actor Admin as Workspace Owner / Admin
    participant AdminAPI as Collaborate Management API
    participant DB as Relational Database
    participant Redis as Redis Cluster (Pub/Sub)
    participant APINodes as API Service Instances (L1 Cache)
    participant WSHub as SignalR / WebSocket Hubs
    actor Client as Removed User (Active Connection)

    Admin->>AdminAPI: Remove User from Workspace
    AdminAPI->>DB: Execute Update Transaction
    DB-->>AdminAPI: Transaction Committed
    AdminAPI->>Redis: 1. Delete L2 Keys (DEL firm:*:ws:{ws_id}:user:{uid}:*)
    AdminAPI->>Redis: 2. PUBLISH collaborate:events:security-revocation { event: USER_REMOVED, ws_id, uid }
    
    par Stateless Invalidation
        Redis-->>APINodes: Broadcast Revocation Event
        APINodes->>APINodes: Evict Matching Keys from L1 Memory Cache
    and Stateful Connection Cutoff
        Redis-->>WSHub: Broadcast Revocation Event
        WSHub->>WSHub: Identify active connection for {ws_id, uid}
        WSHub->>Client: Send 403 Forbidden Frame / Abort In-Flight Ops
        WSHub->>Client: Close WebSocket Connection
    end
```

- **DB Event Hook:** Changes to roles, memberships, or ACLs trigger an event publisher immediately post-commit (via EF Core Interceptors or Transactional Outbox pattern).
- **Pub/Sub Channel:** Published to `collaborate:events:security-revocation`.
- **Immediate Stateless Eviction:** API nodes listening to the channel evict matching local L1 entries. Next HTTP request hits Redis/DB, immediately denying access.
- **Immediate Stateful Disconnect:** SignalR / WebSocket hubs terminate ongoing collaborative editing sessions in real time, aborting uncommitted changes and severing socket connections.

---

### 1.4 On-Behalf-Of (OBO) Delegation & Confused Deputy Prevention

To prevent the **Confused Deputy** problem—where an intermediate service or token is tricked into accessing unauthorized resources—Collaborate implements **OAuth 2.0 Token Exchange (RFC 8693)**.

```mermaid
sequenceDiagram
    autonumber
    actor User as User (Subject C)
    participant CommentSvc as Comment Service (Caller A)
    participant AuthSvc as Collaborate Auth Server
    participant NotifSvc as Notification API (Target B)

    User->>CommentSvc: 1. Post Comment (Bearer User JWT)
    CommentSvc->>AuthSvc: 2. POST /oauth/token (RFC 8693 Token Exchange)
    Note over CommentSvc,AuthSvc: subject_token = User JWT<br/>audience = https://api.caseware.com/notifications<br/>scope = notifications:write
    AuthSvc->>AuthSvc: Verify CommentSvc Entitlements & User Permissions
    AuthSvc-->>CommentSvc: 3. Mint Down-Scoped Downstream JWT
    CommentSvc->>NotifSvc: 4. POST /notifications (Bearer Downstream JWT)
    NotifSvc->>NotifSvc: Validate Audience == Self & Check Scopes
    NotifSvc->>NotifSvc: Log Audit: sub = User, act.sub = CommentSvc
    NotifSvc-->>CommentSvc: 200 OK
```

#### Token Structure & Claim Separation:
- **`sub` (Subject):** Identifies the human user on whose behalf the operation is executed (preserves auditability).
- **`act` (Actor):** Identifies the executing service/system (`act: { "sub": "service_collaborate_comments" }`).
- **`aud` (Audience):** Strictly limited to the target downstream service (e.g., `https://api.caseware.com/notifications`).
- **`scp` / `scope`:** Down-scoped to the minimum necessary operation (`notifications:write`).

#### Downstream Enforcement:
1. **Audience Validation:** ASP.NET Core JWT middleware strictly enforces `ValidateAudience = true`. A token minted for the notification service will be rejected by the financial data service.
2. **Effective Scope Intersection:**
   $$\text{Effective Scope} = \text{User Permissions } (C) \cap \text{Caller Delegation Entitlements } (A) \cap \text{Token Scope}$$
3. **Audit Trail Logging:** All services log both `sub` (original author) and `act.sub` (initiating caller) for regulatory compliance and audit attribution.

---

## 2. Implementation Plan

The implementation strategy focuses on **cloud-native parity**, rapid developer feedback loops via **Test-Driven Development (TDD)**, and modular rollout phases.

```mermaid
gantt
    title Collaborate Identity & Auth Implementation Roadmap
    dateFormat  YYYY-MM-DD
    section Phase 1: Core Foundation
    Local Docker Env & Redis Setup       :p1_1, 2026-09-01, 7d
    ASP.NET Core Base API & Config       :p1_2, after p1_1, 7d
    section Phase 2: Federation & Tokens
    Home Realm Discovery (HRD)           :p2_1, after p1_2, 7d
    OIDC / SAML Broker & PKCE Minting    :p2_2, after p2_1, 10d
    section Phase 3: AuthZ & Revocation
    L1/L2 Multi-Tier Caching Engine      :p3_1, after p2_2, 10d
    Redis Pub/Sub Revocation Hooks       :p3_2, after p3_1, 7d
    SignalR WebSocket Disconnect Engine  :p3_3, after p3_2, 5d
    section Phase 4: Delegation (OBO)
    RFC 8693 Token Exchange Endpoint     :p4_1, after p3_3, 10d
    Confused Deputy Downstream Filters   :p4_2, after p4_1, 7d
    section Phase 5: Cloud Deployment
    AWS ECS Fargate & ElastiCache Deploy :p5_1, after p4_2, 7d
```

### 2.1 Local-to-Cloud Environment Parity & Containerization
- **Containerized Architecture:**
  - Standardized `docker-compose.yml` defining the local topology:
    1. `collaborate-api`: ASP.NET Core Web API container with hot reload support.
    2. `collaborate-redis`: Redis 7 Alpine container for distributed caching and Pub/Sub invalidation channels.
    3. `collaborate-db`: Local PostgreSQL/SQL Server for relational schema and role data.
- **12-Factor Environment Configuration:**
  - Dev, Staging, and Production share identical container definitions and runtimes.
  - Runtime behavior is strictly controlled via environment variables:
    - `REDIS__CONNECTION_STRING`: Local `redis:6379` vs. AWS ElastiCache cluster endpoint.
    - `AUTH__ISSUER_URL`, `AUTH__JWKS_ENDPOINT`: Upstream and internal signing endpoints.
    - `CONNECTION_STRINGS__COLLABORATE_DB`: Local connection string vs. AWS RDS Secrets Manager URI.
- **Cloud Deployment Mapping (AWS):**
  - Local containers deploy directly to **AWS ECS (Fargate)** tasks fronted by AWS Application Load Balancers (ALB).
  - Local Redis container maps directly to **AWS ElastiCache for Redis** (Multi-AZ with auto-failover).

### 2.2 Phased Rollout & Migration Strategy
1. **Phase 1: Core Foundation & Docker Topology**
   - Establish ASP.NET Core project structure, Redis client (`StackExchange.Redis`), and configuration binding.
2. **Phase 2: Authentication & Federation Gateway**
   - Implement `/api/v1/auth/discovery` for email domain parsing.
   - Implement OIDC broker handlers and PKCE exchange logic.
3. **Phase 3: Fine-Grained Authorization & Rapid Revocation**
   - Implement ASP.NET Core `IAuthorizationHandler` evaluating L1 (`IMemoryCache`) $\rightarrow$ L2 (Redis) $\rightarrow$ DB.
   - Implement Redis Pub/Sub background listener for sub-second cache key eviction and WebSocket/SignalR termination.
4. **Phase 4: Token Exchange / Delegation (Scenario C)**
   - Implement RFC 8693 token exchange endpoint for downstream service-to-service and client-to-service calls.
   - Embed actor claims (`act`) and scope-narrowing validation rules.
5. **Phase 5: Cloud Infrastructure & Staging Verification**
   - Package production Docker images, configure AWS ECS task definitions and Terraform/CloudFormation templates.

---

## 3. Testing Strategy

A multi-layered test pyramid built on **Test-Driven Development (TDD)** ensures protocol compliance, permission correctness, and high-concurrency resilience.

```
       / \
      / E2E \       - Full Login, Federation & Collaborative Edit Flows
     /-------\
    /  Integ  \     - WebApplicationFactory + Real Redis Container
   /-----------\
  /    Unit     \   - Policies, Handlers, Claim Extraction & Token Exchange
 /---------------\
```

### 3.1 Unit Testing (Fast Feedback Loop)
- **Authorization Handlers:** Unit test ASP.NET Core `IAuthorizationRequirement` and handlers against mocked `ClaimsPrincipal` contexts.
- **Token Exchange Parser & Validator:** Verify RFC 8693 request parameter parsing (`subject_token`, `audience`, `requested_token_type`).
- **Effective Scope Intersection Engine:** Test mathematical intersection logic:
  $$\text{Effective Scope} = \text{User Permissions} \cap \text{Caller Delegation} \cap \text{Requested Scope}$$

### 3.2 Integration Testing (`WebApplicationFactory`)
- **Containerized Integration Tests:** Spin up real Redis instances via **Testcontainers for .NET** during test suite runs.
- **Federation & PKCE Verification:** Test complete Authorization Code + PKCE challenge verification using simulated upstream OIDC/SAML IdP endpoints.
- **End-to-End API Pipeline:** Test full middleware pipelines including authentication, custom policy handlers, and response serialization.

### 3.3 Scenario C & Confused Deputy Security Tests
- **Audience Mismatch Replay Attacks:** Attempt to present a token minted for `https://api.caseware.com/notifications` to the Financial Data API (`/financial-data`). Assert `401 Unauthorized` / `403 Forbidden` (`ValidateAudience = true`).
- **Privilege Escalation via Delegation:** Attempt to request broader scopes than the original `subject_token` possesses. Assert token exchange rejection (`400 Bad Request: invalid_scope`).
- **Audit Claim Verification:** Assert all minted downstream tokens contain both `sub` (original author) and `act.sub` (calling service), and that downstream controllers record both in audit events.

### 3.4 Rapid Revocation & High-Throughput Load Testing
- **Sub-Second Revocation Benchmark:**
  1. Authenticate user and make requests (populating L1 and L2 caches).
  2. Issue `USER_REMOVED_FROM_WORKSPACE` event via Redis Pub/Sub.
  3. Immediately fire concurrent HTTP requests ($\Delta t < 100\text{ms}$).
  4. Assert all subsequent requests receive `403 Forbidden`.
- **WebSocket / SignalR Active Session Cutoff:**
  1. Open active SignalR connection and begin document editing session.
  2. Trigger user removal.
  3. Assert connection disconnect frame received within $< 1\text{ second}$ and pending document modifications aborted.
- **Throughput & Latency Benchmarks (k6 / NBomber):**
  - Verify sustained 10,000+ checks/second with $p99 < 5\text{ms}$ on L1 cache hits and $p99 < 15\text{ms}$ on L2 Redis cache hits.

---

## 4. Evaluation & Observability

*(To be detailed in next step)*

---

## 5. Failure Modes & Tradeoffs

*(To be detailed in next step)*


