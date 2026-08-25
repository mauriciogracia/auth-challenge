# Design Decisions & Notes

## 1. Architectural Choices

- **Technology Stack:**
  - Backend: C# / ASP.NET Core Web API (REST / JSON).
  - Infrastructure: AWS-aligned cloud setup.
  - Caching / Invalidation: Direct connection from ASP.NET Core controllers/middleware to Redis (e.g., via `StackExchange.Redis`) for sub-millisecond lookups and Redis Pub/Sub for distributed cache invalidation.

## 2. Implementation Choice (Part 2)

- **Selected Option:** **Option C — On-Behalf-Of (OBO) Token Exchange Endpoint**
  - Standard: OAuth 2.0 Token Exchange (RFC 8693).
  - Key Objectives:
    - Solve downstream service-to-service and client-to-service delegation.
    - Scope-down and narrow audience/permissions for downstream calls.
    - Prevent the "confused deputy" vulnerability.
    - Preserve subject identity and actor attribution (`act` claim) for audit logs.

## 3. Authentication & Federation Flow Design

- **User Discovery (Home Realm Discovery):**
  - **Email-First Input:** Frontend renders an email entry screen prior to authentication.
  - **Domain Lookup:** An initial unauthenticated endpoint (`/api/v1/auth/discovery?email=user@domain.com`) parses the domain:
    - Matches internal firm domains to redirect to **Caseware Central IdP**.
    - Matches configured enterprise domains or tenant workspaces to redirect to the firm's federated **SAML 2.0 / OIDC IdP**.
    - Defaults unfederated external users to standard Collaborate invite/local credentials.

- **Collaborate as Federation Broker (Relying Party):**
  - Collaborate Auth Service acts as an **OIDC Relying Party (RP)** to upstream IdPs while acting as the **OAuth 2.0 Authorization Server** to internal Collaborate applications.
  - Frontend initiates **OAuth 2.0 Authorization Code Flow + PKCE** (`code_challenge` / `code_verifier`) against Collaborate's `/authorize` endpoint.
  - Collaborate preserves client state and PKCE parameters, then redirects the user's browser to the discovered upstream IdP.

- **Callback & Upstream Assertion Processing:**
  - Upstream IdP validates credentials/MFA and redirects back to Collaborate's redirect URI (`/auth/callback/caseware` or `/auth/callback/saml`).
  - Collaborate verifies upstream signature, validates claims, and maps the external identity (`email`, `upn`, `name_id`) to the internal Collaborate user record and firm membership.

- **Token Minting:**
  - Collaborate completes the PKCE exchange with the calling client application.
  - Collaborate signs and issues its own standard **RS256 JWT Access Token** scoped for downstream Collaborate APIs (Documents, Financial Data, Comments).
  - Token payload contains standardized claims:
    - `sub`: Collaborate internal user ID.
    - `tenant_id` / `firm_id`: Current firm context.
    - `user_type`: `firm_staff` vs. `external_client`.
    - `jti` / `sid`: Unique token and session identifiers for rapid revocation tracking.

## 4. Permission Checking, Multi-Tier Caching & Real-Time Revocation

- **Multi-Tier Caching Architecture:**
  - **L1 (In-Memory per Service Instance):** Uses ASP.NET Core `IMemoryCache` with a short sliding expiration (e.g., 30–60 seconds). Fast path serving 10k+ checks/sec with zero network hops.
  - **L2 (Distributed Redis Cluster):** Shared cache between service replicas with a standard TTL (e.g., 10–15 minutes).
    - Structured cache key pattern:
      - Workspace role: `firm:{firm_id}:ws:{workspace_id}:user:{user_id}:role`
      - Resource override: `firm:{firm_id}:res:{resource_id}:user:{user_id}:acl`
  - **Database (Source of Truth):** Relational store housing roles, firm policies, and resource ACLs. Queried only on L1/L2 cache misses.

- **Evaluation Strategy (Hybrid RBAC + ABAC):**
  - **Coarse Claims in Access Token:** Embed non-volatile context like `firm_id`, `user_id`, and `user_type` in the JWT.
  - **Dynamic Permission Resolution:**
    - Downstream API checks L1 for `(user_id, resource_id, action)`.
    - If missing, check L2 Redis.
    - If missing, fetch from DB, compute effective permission (`Firm Policy ∧ Workspace Role ∨ Resource Override`), and write back to L2 + L1.

- **Real-Time Revocation via Redis Pub/Sub:**
  - **DB Event Hook:** On any role update, user removal, or ACL change, the DB transaction commits and triggers an event publisher (e.g., via EF Core Interceptors or Transactional Outbox).
  - **Event Payload:**
    - `EventType`: `USER_REMOVED_FROM_WORKSPACE`, `RESOURCE_ACL_CHANGED`, or `SESSION_REVOKED`.
    - `Metadata`: `{ firm_id, workspace_id, resource_id, user_id, timestamp }`.
  - **Redis Channel:** Published to `collaborate:events:security-revocation`.

- **Handling Sub-Second Invalidation & Active Connections:**
  - **Stateless HTTP APIs:** Every API node subscribes to the Redis revocation channel. Upon receiving the event, the node evicts the targeted keys from its local L1 memory cache and invalidates L2 Redis keys immediately. The next HTTP request fails the authorization check without waiting for token expiration.
  - **Long-Lived Connections & WebSockets (Collaborative Editing):** SignalR / WebSocket hubs subscribe to the same Redis channel. When a `USER_REMOVED_FROM_WORKSPACE` event arrives for an active `user_id` on that workspace, the hub:
    - Aborts any in-flight document operations.
    - Sends a `403 Forbidden` / disconnect frame to the client.
    - Closes the underlying WebSocket/SignalR connection immediately.

## 5. On-Behalf-Of (OBO) Delegation & Confused Deputy Mitigation

- **Claim Structure & Identity Tracking:**
  - Every minted downstream token explicitly separates the target audience, the original user, and the executing caller:
    - `sub` (Subject): The original user (User C). Ensures audit logs attribute data access directly to the user.
    - `act` (Actor Claim): The calling entity (Service/App A). Contains `{ "sub": "client_app_id" | "notification_service" }`.
    - `aud` (Audience): The specific target downstream resource (e.g., `https://api.caseware.com/notifications`). A token issued for the notification service will fail validation if sent to the financial data service.
    - `scope` / `scp`: Down-scoped, narrow permissions (e.g., `notifications:write`), never broad administrator scopes.
  - **Token Sample:**
    ```json
    {
      "iss": "https://auth.collaborate.caseware.com",
      "sub": "usr_98765",
      "aud": "https://api.caseware.com/notifications",
      "client_id": "service_collaborate_comments",
      "act": {
        "sub": "service_collaborate_comments"
      },
      "scp": ["notifications:write"],
      "firm_id": "firm_123",
      "exp": 1756080000
    }
    ```

- **Flow per Scenario:**
  - **Scenario (a) External Client System to Collaborate API:**
    - External system authenticates with Collaborate Auth using its own credentials plus an existing delegation grant or user consent (`grant_type=urn:ietf:params:oauth:grant-type:token-exchange`).
    - Collaborate Auth verifies that the external system is authorized by the firm to impersonate/delegate for that employee.
    - Issues a token with `sub=employee_id`, `act={"sub": "client_system_id"}`, and strictly requested scopes (e.g., `engagements:read`).
  - **Scenario (b) Service-to-Service (Comments -> Notification API):**
    - When a user posts a comment, Collaborate Comment API holds the user's incoming Bearer token.
    - Comment API calls Collaborate Auth Token Exchange endpoint, presenting the user's token (`subject_token`) and requesting audience `aud=notification_api`.
    - Collaborate Auth checks if Comment API is authorized to request this downstream exchange, mints a fresh token containing `aud=notification_api`, `sub=user_id`, and `act={"sub": "comment_service"}`.

- **Downstream Validation Rules (Mitigating Confused Deputy):**
  - **Audience Enforcement (`ValidateAudience = true` in ASP.NET Core):** Downstream API strictly rejects any token where `aud` does not match its own identifier.
  - **Effective Permission Computation:** The downstream API evaluates permissions using the intersection:
    $$\text{Effective Scope} = \text{User Permissions } (C) \cap \text{Caller Delegation Entitlements } (A) \cap \text{Token Scope}$$
  - **Audit Trail Preservation:** Both `sub` and `act.sub` are written to access/audit logs so security teams know which service acted on whose behalf.

## 6. Implementation Strategy & Cloud Parity

- **Local-to-Cloud Environment Parity:**
  - Container-first design: Architecture runs identically locally in Docker as in AWS cloud containers.
  - Multi-container setup: Dedicated container for Redis and dedicated container for the ASP.NET Core API.
  - Cloud mapping: Local Docker Compose translates directly to AWS ECS/Fargate (tasks) + AWS ElastiCache for Redis in staging/prod.
  - 12-Factor configuration: Environment variables govern Dev vs. Staging vs. Prod settings (Redis endpoints, JWT signing keys/JWKS URLs, IdP endpoints).

- **TDD & Test Strategy Emphasis:**
  - Test-Driven Development (TDD) and integration testing prioritized.
  - Specific focus on testing **Scenario C (On-Behalf-Of Token Exchange)**:
    - Verifying subject vs. actor claim attribution.
    - Scope narrowing & audience restrictions.
    - Confused deputy protection tests.
  - Dedicated tests for **rapid sub-second permission revocation**:
    - Validating instant cache eviction upon role removal.
    - Ensuring immediate failure on subsequent requests without token expiry delay.


