using System.Security.Claims;
using Collaborate.Auth.Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Collaborate.Auth.Api.Controllers;

/// <summary>
/// Sample downstream resource endpoints to demonstrate audience enforcement
/// and actor claim audit verification (Scenario C).
/// </summary>
[ApiController]
[Route("api")]
[Authorize]
public sealed class DownstreamSamplesController : ControllerBase
{
    private readonly ILogger<DownstreamSamplesController> _logger;

    public DownstreamSamplesController(ILogger<DownstreamSamplesController> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Notification endpoint expecting audience 'https://api.caseware.com/notifications'
    /// and scope 'notifications:write'.
    /// </summary>
    [HttpPost("notifications")]
    public IActionResult SendNotification([FromBody] NotificationMessage message)
    {
        var subjectUser = User.FindFirst(SecurityConstants.Claims.Subject)?.Value
                          ?? User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var actorJson = User.FindFirst(SecurityConstants.Claims.Actor)?.Value;
        var scopes = User.FindAll(c => c.Type == SecurityConstants.Claims.Scope || c.Type == "scope" || c.Type == "http://schemas.microsoft.com/identity/claims/scope")
            .SelectMany(c => c.Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (!scopes.Contains("notifications:write"))
        {
            return Forbid();
        }

        _logger.LogInformation(
            "AUDIT LOG: Notification dispatched. Target Subject User: {Subject}, Executing Actor: {Actor}, Payload: {Message}",
            subjectUser,
            actorJson,
            message.Content);

        return Ok(new
        {
            Status = "Notification dispatched",
            SubjectUser = subjectUser,
            Actor = actorJson,
            Message = message.Content
        });
    }

    /// <summary>
    /// Document endpoint expecting scope 'documents:read'.
    /// </summary>
    [HttpGet("documents/{documentId}")]
    public IActionResult GetDocument(string documentId)
    {
        var subjectUser = User.FindFirst(SecurityConstants.Claims.Subject)?.Value;
        var actorJson = User.FindFirst(SecurityConstants.Claims.Actor)?.Value;
        var scopes = User.FindAll(SecurityConstants.Claims.Scope).Select(c => c.Value).ToHashSet();

        if (!scopes.Contains("documents:read"))
        {
            return Forbid();
        }

        return Ok(new
        {
            DocumentId = documentId,
            SubjectUser = subjectUser,
            Actor = actorJson,
            Title = "Confidential Financial Audit Report 2026"
        });
    }
}

public sealed record NotificationMessage(string Content);
