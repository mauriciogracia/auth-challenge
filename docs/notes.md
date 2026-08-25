# Engineering Notes & Architecture Decision Log

**Project:** Caseware Collaborate Identity & Authorization Platform  
**Target:** C# / ASP.NET Core (.NET 8), Redis, AWS  

---

## 1. What Are We Actually Solving? (The Business & Product Context)

Collaborate is Caseware's shared engagement workspace where accounting firms, audit teams, external client stakeholders (CFOs, controllers), and third-party reviewers collaborate on active engagements in real time. 

From a product and business standpoint, this introduces three distinct challenges that break standard out-of-the-box identity setups:

1. **Cross-Boundary Multi-Tenancy & Federation:** 
   - A single audit engagement workspace contains people from different organizations. 
   - Firm staff want Single Sign-On (SSO) through Caseware Central IdP or their own enterprise Azure AD / Okta, while external client guests may need federated SAML or direct invitations. We cannot present users with a messy list of 20 login buttons.
2. **Real-Time Collaboration at Scale (10k+ checks/sec):**
   - When multiple auditors and clients are concurrently reviewing workpapers, adding comments, and streaming financial extracts, permission checks fire rapidly on every interaction.
   - Hitting a relational database on every keystroke or REST call would quickly overwhelm the database and introduce noticeable UI latency.
3. **Sub-Second Access Revocation for Compliance:**
   - In financial audit and assurance, access control is a regulatory requirement. 
   - If an external contractor or auditor is removed from an engagement, their access must terminate immediately—including ongoing collaborative editing sessions—without waiting 15 to 60 minutes for access tokens to expire.
4. **Safe Automation & Service Delegation (Avoiding Confused Deputy):**
   - Automated client ERP integrations pull data on behalf of staff, and internal microservices (e.g., Comments posting a Notification) act on behalf of users.
   - If services pass full user tokens downstream, a compromised background worker could access unauthorized financial records. We must strictly isolate downstream scope and audience while preserving a clear audit trail.

---

## 2. Key Architecture Decisions & The "Why" Behind Them

### Decision 1: Email-First Home Realm Discovery (HRD)
* **The Problem:** How to route firm staff, federated corporate clients, and external guests to their respective identity providers seamlessly.
* **The Choice:** An email-first discovery endpoint (`GET /api/v1/auth/discovery?email=...`) that inspects the domain before triggering the OAuth2 Authorization Code + PKCE flow.
* **Why:** 
  - Users only need to enter their work email; the system transparently routes `@firm.com` to their enterprise SAML/OIDC provider and `@caseware.com` to Central IdP.
  - Keeps downstream Collaborate services completely agnostic of upstream identity complexity. Collaborate Auth acts as a federation broker (Relying Party to upstream IdPs, Authorization Server to Collaborate apps).

---

### Decision 2: Hybrid Authorization Model (Coarse JWT Claims + Dynamic Caching)
* **The Problem:** Should we embed all user permissions inside the JWT token, or query the database on every request?
* **Why Not Pure JWT Claims?** In an enterprise audit tool, a user might have access to dozens of workspaces and hundreds of specific document overrides. Embedding fine-grained permissions causes massive token bloat (HTTP header size limits) and makes instant revocation impossible until token expiry.
* **Why Not Pure Database Queries?** Querying SQL for every document fetch and comment post creates unacceptable database load ($10\text{k}+$ queries/sec) and degrades real-time responsiveness.
* **The Solution:** 
  - JWT tokens carry only coarse, stable identity metadata (`sub`, `firm_id`, `user_type`, `jti`).
  - Fine-grained permission resolution uses a **multi-tier caching abstraction (`IPermissionStore`)**:
    - **L1 (In-Memory `IMemoryCache`, 30–60s):** Fast path serving repeated checks on the same API node with zero network hops ($<1\text{ms}$).
    - **L2 (Distributed Redis Cluster, 10–15m):** Shared across all API replicas to absorb traffic spikes ($<5\text{ms}$).
    - **Relational DB:** Queried only on cache misses to compute effective permissions:
      $$\text{Effective Permission} = \text{Firm Policy} \land (\text{Workspace Role} \lor \text{Resource Override})$$

---

### Decision 3: Sub-Second Revocation via Redis Pub/Sub
* **The Problem:** How to cut off access immediately when a user is removed from a workspace, even if their JWT token is technically still valid.
* **The Solution:** 
  - When a role or membership changes in the database, the transaction commit publishes an invalidation event to Redis Pub/Sub (`collaborate:events:security-revocation`).
  - **Stateless REST APIs:** Nodes listening to the channel evict the targeted keys from local L1 memory. The user's next HTTP request misses L1/L2 and gets blocked at the database level.
  - **Live Collaborative Sessions (SignalR / WebSockets):** Hubs intercept the event, abort in-flight document edits, send a `403 Forbidden` disconnect frame, and terminate the socket connection immediately.
  - **Safety Net:** The short L1 TTL (30–60s) ensures that even if a pub/sub message is dropped during a network blip, stale access is strictly bounded to under a minute.

---

### Decision 4: RFC 8693 Token Exchange for On-Behalf-Of (OBO) Delegation
* **The Problem:** Two delegation scenarios:
  1. A client's ERP integration calls Collaborate on behalf of an employee.
  2. Internal Comments Service calls the Notification API on behalf of a user who posted a comment.
* **The Vulnerability (Confused Deputy):** If the Comment Service simply forwards the user's incoming bearer token to the Notification API, or uses its own admin credentials, a vulnerability in the Comment Service could be exploited to access sensitive financial data or impersonate arbitrary users.
* **The Solution:** We implemented **OAuth 2.0 Token Exchange (RFC 8693)** at `POST /oauth/token`:
  - **Audience Lockdown (`aud`):** The exchanged token is cryptographically restricted to `https://api.caseware.com/notifications`. If sent to the Financial Data API, ASP.NET Core's JWT middleware immediately rejects it.
  - **Actor Attribution (`act`):** The token clearly separates the human subject (`sub: usr_auditor_01`) from the executing service (`act: { "sub": "service_collaborate_comments" }`), ensuring complete audit traceability.
  - **Scope Math:** The issued scope is strictly calculated as:
    $$\text{Effective Scope} = \text{User Entitlements} \cap \text{Caller Delegation Allowance} \cap \text{Requested Scope}$$
  - A caller can never escalate privileges beyond what the original user is allowed to do.

---

## 3. Targeted Implementation (Why Option C?)

For the practical coding slice (Part 2), **Option C (On-Behalf-Of Delegation Endpoint)** was selected because:
1. **Highest Security Impact:** Delegation and Confused Deputy vulnerabilities represent the most critical attack vector in modern distributed systems.
2. **Demonstrates Senior Architectural Judgment:** Implementing RFC 8693 demonstrates how to leverage built-in framework capabilities (`JwtSecurityTokenHandler`, `ClaimsPrincipal`, ASP.NET Core Bearer validation) rather than hand-rolling custom cryptography or proprietary tokens.
3. **End-to-End Testability:** Allowed building a complete, verifiable flow:
   - Exchanging user tokens via `POST /oauth/token`
   - Down-scoping and actor claim injection
   - Protecting downstream resource endpoints (`POST /api/notifications`)
   - Interactive exploration and contract documentation via **Swagger UI** at `/`

---

## 4. Operational & Reliability Decisions

* **Data Abstraction Layer (`IPermissionStore`):** 
  - Controllers never touch Redis or SQL directly. All interactions go through clean interfaces, allowing seamless unit testing and mocking.
  - If Redis experiences an outage, a Polly circuit breaker gracefully degrades to querying the database directly, keeping the system online while logging alerts to Datadog.
* **Fail-Closed Security Default:**
  - If both cache and database are unreachable, the system defaults to Deny (`403 Forbidden` / `503 Service Unavailable`). It will never grant unauthorized access due to infrastructure failure.
* **Observability & Audit Trail:**
  - Distributed W3C tracing propagates `traceparent` across microservice hops.
  - Structured JSON audit logs record both `sub` (original author) and `act.sub` (delegated caller) for regulatory and compliance audits.
* **Local-to-Cloud Environment Parity:**
  - Designed for 12-factor cloud deployment (AWS ECS Fargate + AWS ElastiCache for Redis).
  - For this take-home exercise, container configurations are specified in the architecture document, while local execution runs directly via `.NET 8 SDK` and in-memory stores for instant zero-dependency review and testing.
