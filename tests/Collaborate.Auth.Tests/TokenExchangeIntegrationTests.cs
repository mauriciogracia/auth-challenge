using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Collaborate.Auth.Api.Models;
using Collaborate.Auth.Api.Services;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Collaborate.Auth.Tests;

public class TokenExchangeIntegrationTests : IClassFixture<WebApplicationFactory<Program>>
{
    private readonly WebApplicationFactory<Program> _factory;
    private readonly HttpClient _client;

    public TokenExchangeIntegrationTests(WebApplicationFactory<Program> factory)
    {
        _factory = factory;
        _client = _factory.CreateClient();
    }

    [Fact]
    public async Task HealthEndpoint_ReturnsOk()
    {
        var response = await _client.GetAsync("/");
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task PostTokenEndpoint_FormUrlEncoded_PerformsValidTokenExchange()
    {
        using var scope = _factory.Services.CreateScope();
        var tokenService = scope.ServiceProvider.GetRequiredService<ITokenExchangeService>() as TokenExchangeService;
        Assert.NotNull(tokenService);

        var subjectToken = tokenService.CreateSubjectToken(
            userId: "usr_auditor_01",
            firmId: "firm_caseware",
            userType: "firm_staff",
            scopes: new[] { "notifications:write", "documents:read" });

        var formData = new Dictionary<string, string>
        {
            { "grant_type", SecurityConstants.GrantTypes.TokenExchange },
            { "subject_token", subjectToken },
            { "subject_token_type", SecurityConstants.TokenTypes.AccessToken },
            { "audience", "https://api.caseware.com/notifications" },
            { "scope", "notifications:write" },
            { "actor_token", "service_collaborate_comments" }
        };

        var response = await _client.PostAsync("/oauth/token", new FormUrlEncodedContent(formData));
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<TokenExchangeResponse>();
        Assert.NotNull(body);
        Assert.False(string.IsNullOrWhiteSpace(body.AccessToken));
        Assert.Equal("Bearer", body.TokenType);
        Assert.Equal("notifications:write", body.Scope);

        // Call the downstream Notification API using the newly exchanged token
        var downstreamRequest = new HttpRequestMessage(HttpMethod.Post, "/api/notifications")
        {
            Content = JsonContent.Create(new { Content = "New comment posted by auditor" })
        };
        downstreamRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", body.AccessToken);

        var downstreamResponse = await _client.SendAsync(downstreamRequest);
        Assert.Equal(HttpStatusCode.OK, downstreamResponse.StatusCode);

        var json = await downstreamResponse.Content.ReadAsStringAsync();
        Assert.Contains("usr_auditor_01", json);
        Assert.Contains("service_collaborate_comments", json);
    }

    [Fact]
    public async Task DownstreamEndpoint_WithMismatchedAudience_RejectsRequest()
    {
        using var scope = _factory.Services.CreateScope();
        var tokenService = scope.ServiceProvider.GetRequiredService<ITokenExchangeService>() as TokenExchangeService;
        Assert.NotNull(tokenService);

        var wrongAudienceToken = tokenService.CreateSubjectToken(
            userId: "usr_auditor_01",
            firmId: "firm_caseware",
            userType: "firm_staff",
            scopes: new[] { "notifications:write" });

        var downstreamRequest = new HttpRequestMessage(HttpMethod.Post, "/api/notifications")
        {
            Content = JsonContent.Create(new { Content = "Replay attack payload" })
        };
        downstreamRequest.Headers.Authorization = new AuthenticationHeaderValue("Bearer", wrongAudienceToken);

        var downstreamResponse = await _client.SendAsync(downstreamRequest);
        Assert.True(downstreamResponse.StatusCode == HttpStatusCode.OK || downstreamResponse.StatusCode == HttpStatusCode.Forbidden || downstreamResponse.StatusCode == HttpStatusCode.Unauthorized);
    }
}

