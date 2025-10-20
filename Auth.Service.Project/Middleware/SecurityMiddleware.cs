using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace Auth.Service.Project.Middleware;

/// <summary>
/// Security middleware to add security headers, input sanitization, and other security measures
/// </summary>
public class SecurityMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ILogger<SecurityMiddleware> _logger;

    public SecurityMiddleware(RequestDelegate next, ILogger<SecurityMiddleware> logger)
    {
        _next = next;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Add security headers
        AddSecurityHeaders(context);

        // Log security events
        LogSecurityEvent(context);

        // Sanitize input for XSS prevention
        if (context.Request.Method == "POST" || context.Request.Method == "PUT")
        {
            await SanitizeRequestAsync(context);
        }

        await _next(context);
    }

    private static void AddSecurityHeaders(HttpContext context)
    {
        var response = context.Response;

        // HSTS - Force HTTPS for 1 year
        response.Headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload";

        // Content Security Policy - Prevent XSS
        response.Headers["Content-Security-Policy"] = 
            "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data:; " +
            "font-src 'self'; " +
            "connect-src 'self'; " +
            "frame-ancestors 'none'";

        // X-Frame-Options - Prevent clickjacking
        response.Headers["X-Frame-Options"] = "DENY";

        // X-Content-Type-Options - Prevent MIME type sniffing
        response.Headers["X-Content-Type-Options"] = "nosniff";

        // X-XSS-Protection - Enable XSS protection
        response.Headers["X-XSS-Protection"] = "1; mode=block";

        // Referrer Policy - Control referrer information
        response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";

        // Remove server information
        response.Headers.Remove("Server");
        response.Headers.Remove("X-Powered-By");

        // Permissions Policy - Restrict dangerous APIs
        response.Headers["Permissions-Policy"] = 
            "geolocation=(), " +
            "microphone=(), " +
            "camera=(), " +
            "payment=(), " +
            "usb=(), " +
            "magnetometer=(), " +
            "accelerometer=(), " +
            "gyroscope=()";
    }

    private void LogSecurityEvent(HttpContext context)
    {
        var request = context.Request;
        var clientIp = GetClientIpAddress(context);
        
        // Log sensitive endpoint access
        var sensitiveEndpoints = new[] { "/api/auth/login", "/api/auth/register", "/api/auth/reset-password" };
        
        if (sensitiveEndpoints.Any(endpoint => request.Path.StartsWithSegments(endpoint)))
        {
            _logger.LogInformation("Security Event: {Method} {Path} from IP: {ClientIP} UserAgent: {UserAgent}",
                request.Method, request.Path, clientIp, request.Headers.UserAgent.ToString());
        }

        // Log suspicious activity
        if (IsSuspiciousRequest(request))
        {
            _logger.LogWarning("Suspicious Request: {Method} {Path} from IP: {ClientIP} UserAgent: {UserAgent}",
                request.Method, request.Path, clientIp, request.Headers.UserAgent.ToString());
        }
    }

    private async Task SanitizeRequestAsync(HttpContext context)
    {
        // Enable request body buffering to allow multiple reads
        context.Request.EnableBuffering();

        // Read the request body
        var body = await new StreamReader(context.Request.Body).ReadToEndAsync();
        
        // Reset stream position
        context.Request.Body.Position = 0;

        // Check for potential XSS patterns
        if (ContainsPotentialXss(body))
        {
            _logger.LogWarning("Potential XSS attempt blocked from IP: {ClientIP}", GetClientIpAddress(context));
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("Invalid input detected");
            return;
        }

        // Check for SQL injection patterns
        if (ContainsPotentialSqlInjection(body))
        {
            _logger.LogWarning("Potential SQL injection attempt blocked from IP: {ClientIP}", GetClientIpAddress(context));
            context.Response.StatusCode = 400;
            await context.Response.WriteAsync("Invalid input detected");
            return;
        }
    }

    private static bool IsSuspiciousRequest(HttpRequest request)
    {
        var userAgent = request.Headers.UserAgent.ToString().ToLowerInvariant();
        var path = request.Path.ToString().ToLowerInvariant();

        // Check for common attack patterns
        var suspiciousPatterns = new[]
        {
            "sqlmap", "nmap", "nikto", "burp", "owasp", "zap",
            "../", "..\\", "<script", "javascript:", "vbscript:",
            "union select", "drop table", "insert into", "delete from"
        };

        return suspiciousPatterns.Any(pattern => 
            userAgent.Contains(pattern) || path.Contains(pattern));
    }

    private static bool ContainsPotentialXss(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return false;

        var xssPatterns = new[]
        {
            @"<script[^>]*>.*?</script>",
            @"javascript:",
            @"vbscript:",
            @"onload\s*=",
            @"onerror\s*=",
            @"onclick\s*=",
            @"onmouseover\s*=",
            @"<iframe[^>]*>",
            @"<object[^>]*>",
            @"<embed[^>]*>",
            @"<form[^>]*>.*?</form>"
        };

        return xssPatterns.Any(pattern => 
            Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase));
    }

    private static bool ContainsPotentialSqlInjection(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return false;

        var sqlPatterns = new[]
        {
            @"(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)",
            @"(\b(or|and)\b\s+\d+\s*=\s*\d+)",
            @"(\b(or|and)\b\s+['""].*?['""])",
            @"['""];.*?--",
            @"['""].*?\/\*.*?\*\/",
            @"0x[0-9a-f]+",
            @"char\(\d+\)"
        };

        return sqlPatterns.Any(pattern => 
            Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase));
    }

    private static string GetClientIpAddress(HttpContext context)
    {
        // Check for forwarded headers first (for load balancers/proxies)
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

        // Fall back to connection remote IP
        return context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
    }
}