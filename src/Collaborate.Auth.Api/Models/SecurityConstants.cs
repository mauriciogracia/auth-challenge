namespace Collaborate.Auth.Api.Models;

// Standard OAuth 2.0 & RFC 8693 strings in one spot so we don't scatter magic strings or typos around.
public static class SecurityConstants

{
    public static class GrantTypes
    {
        // RFC 8693 Token Exchange grant type for On-Behalf-Of delegation
        public const string TokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange";
        public const string AuthorizationCode = "authorization_code";
        public const string ClientCredentials = "client_credentials";
    }

    public static class TokenTypes
    {
        // Standard OAuth token type URIs
        public const string AccessToken = "urn:ietf:params:oauth:token-type:access_token";
        public const string IdToken = "urn:ietf:params:oauth:token-type:id_token";
        public const string Jwt = "urn:ietf:params:oauth:token-type:jwt";
    }

    public static class Claims
    {
        // Standard OIDC & RFC 8693 claims
        public const string Subject = "sub";       // The human user on whose behalf the call is made
        public const string Actor = "act";         // The calling service/client performing the action
        public const string Audience = "aud";      // Downstream target service identifier
        public const string Scope = "scp";         // Down-scoped permissions for downstream APIs
        
        // Multi-tenant & identity metadata
        public const string TenantId = "tenant_id";
        public const string FirmId = "firm_id";
        public const string UserType = "user_type";
        public const string ClientId = "client_id";
        public const string JwtId = "jti";         // Unique token ID for revocation tracking
    }

    public static class Errors
    {
        // Standard OAuth 2.0 / RFC 8693 error responses
        public const string InvalidRequest = "invalid_request";
        public const string InvalidGrant = "invalid_grant";
        public const string UnauthorizedClient = "unauthorized_client";
        public const string UnsupportedGrantType = "unsupported_grant_type";
        public const string InvalidScope = "invalid_scope";
        public const string InvalidTarget = "invalid_target";
    }
}

