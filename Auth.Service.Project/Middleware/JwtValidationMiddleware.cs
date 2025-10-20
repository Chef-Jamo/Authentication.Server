using Auth.Service.Project.Services;
using Microsoft.AspNetCore.Authorization;

namespace Auth.Service.Project.Middleware;

/// <summary>
/// Middleware to validate JWT tokens against blacklist
/// </summary>
public class JwtValidationMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<JwtValidationMiddleware> _logger;

    public JwtValidationMiddleware(RequestDelegate next, ILogger<JwtValidationMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context, IJwtBlacklistService blacklistService)
    {
        // Only check tokens for endpoints that require authorization
        var endpoint = context.GetEndpoint();
        var hasAuthorizeAttribute = endpoint?.Metadata?.GetMetadata<AuthorizeAttribute>() != null;

        if (hasAuthorizeAttribute)
        {
            var token = GetTokenFromRequest(context.Request);
            
            if (!string.IsNullOrEmpty(token))
            {
                try
                {
                    if (await blacklistService.IsTokenBlacklistedAsync(token))
                    {
                        _logger.LogWarning("Blocked request with blacklisted token from IP: {ClientIP}", 
                            GetClientIpAddress(context));
                        
                        context.Response.StatusCode = 401;
                        await context.Response.WriteAsync("Token has been revoked");
                        return;
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error checking token blacklist");
                    // Continue processing - don't block valid requests due to blacklist errors
                }
            }
        }

        await _next(context);
    }

    private static string? GetTokenFromRequest(HttpRequest request)
    {
        var authHeader = request.Headers.Authorization.FirstOrDefault();
        
        if (authHeader != null && authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return authHeader.Substring("Bearer ".Length).Trim();
        }

        return null;
    }

    private static string GetClientIpAddress(HttpContext context)
    {
        var xForwardedFor = context.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrEmpty(xForwardedFor))
        {
            return xForwardedFor.Split(',')[0].Trim();
        }

        var xRealIp = context.Request.Headers["X-Real-IP"].FirstOrDefault();
        if (!string.IsNullOrEmpty(xRealIp))
        {
            return xRealIp;
        }

        return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }
}