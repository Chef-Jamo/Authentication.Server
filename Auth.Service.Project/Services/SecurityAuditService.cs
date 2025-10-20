namespace Auth.Service.Project.Services;

/// <summary>
/// Security audit logging service for tracking security-related events
/// </summary>
public interface ISecurityAuditService
{
    /// <summary>
    /// Logs successful login attempts
    /// </summary>
    Task LogSuccessfulLoginAsync(string email, string clientIp, string userAgent);

    /// <summary>
    /// Logs failed login attempts
    /// </summary>
    Task LogFailedLoginAsync(string email, string clientIp, string userAgent, string reason);

    /// <summary>
    /// Logs account lockout events
    /// </summary>
    Task LogAccountLockoutAsync(string email, string clientIp, int failedAttempts);

    /// <summary>
    /// Logs password changes
    /// </summary>
    Task LogPasswordChangeAsync(Guid userId, string email, string clientIp, bool successful);

    /// <summary>
    /// Logs password reset requests
    /// </summary>
    Task LogPasswordResetRequestAsync(string email, string clientIp);

    /// <summary>
    /// Logs suspicious activities
    /// </summary>
    Task LogSuspiciousActivityAsync(string activity, string clientIp, string userAgent, string? userId = null);

    /// <summary>
    /// Logs token blacklisting events
    /// </summary>
    Task LogTokenBlacklistedAsync(string? userId, string clientIp, string reason);

    /// <summary>
    /// Logs rate limiting violations
    /// </summary>
    Task LogRateLimitViolationAsync(string endpoint, string clientIp, string userAgent);

    /// <summary>
    /// Logs configuration security issues
    /// </summary>
    Task LogSecurityConfigurationIssueAsync(string issue, string severity);
}

public class SecurityAuditService : ISecurityAuditService
{
    private readonly ILogger<SecurityAuditService> _logger;

    public SecurityAuditService(ILogger<SecurityAuditService> logger)
    {
        _logger = logger;
    }

    public async Task LogSuccessfulLoginAsync(string email, string clientIp, string userAgent)
    {
        _logger.LogInformation(
            "SECURITY_AUDIT: Successful login for user {Email} from IP {ClientIP} with UserAgent {UserAgent} at {Timestamp}",
            email, clientIp, userAgent, DateTime.UtcNow);
        
        await Task.CompletedTask;
    }

    public async Task LogFailedLoginAsync(string email, string clientIp, string userAgent, string reason)
    {
        _logger.LogWarning(
            "SECURITY_AUDIT: Failed login attempt for user {Email} from IP {ClientIP} with UserAgent {UserAgent}. Reason: {Reason} at {Timestamp}",
            email, clientIp, userAgent, reason, DateTime.UtcNow);
        
        await Task.CompletedTask;
    }

    public async Task LogAccountLockoutAsync(string email, string clientIp, int failedAttempts)
    {
        _logger.LogWarning(
            "SECURITY_AUDIT: Account locked for user {Email} from IP {ClientIP} after {FailedAttempts} failed attempts at {Timestamp}",
            email, clientIp, failedAttempts, DateTime.UtcNow);
        
        await Task.CompletedTask;
    }

    public async Task LogPasswordChangeAsync(Guid userId, string email, string clientIp, bool successful)
    {
        if (successful)
        {
            _logger.LogInformation(
                "SECURITY_AUDIT: Password changed successfully for user {UserId} ({Email}) from IP {ClientIP} at {Timestamp}",
                userId, email, clientIp, DateTime.UtcNow);
        }
        else
        {
            _logger.LogWarning(
                "SECURITY_AUDIT: Failed password change attempt for user {UserId} ({Email}) from IP {ClientIP} at {Timestamp}",
                userId, email, clientIp, DateTime.UtcNow);
        }
        
        await Task.CompletedTask;
    }

    public async Task LogPasswordResetRequestAsync(string email, string clientIp)
    {
        _logger.LogInformation(
            "SECURITY_AUDIT: Password reset requested for email {Email} from IP {ClientIP} at {Timestamp}",
            email, clientIp, DateTime.UtcNow);
        
        await Task.CompletedTask;
    }

    public async Task LogSuspiciousActivityAsync(string activity, string clientIp, string userAgent, string? userId = null)
    {
        _logger.LogWarning(
            "SECURITY_AUDIT: Suspicious activity detected - {Activity} from IP {ClientIP} with UserAgent {UserAgent}. UserId: {UserId} at {Timestamp}",
            activity, clientIp, userAgent, userId ?? "Unknown", DateTime.UtcNow);
        
        await Task.CompletedTask;
    }

    public async Task LogTokenBlacklistedAsync(string? userId, string clientIp, string reason)
    {
        _logger.LogInformation(
            "SECURITY_AUDIT: Token blacklisted for user {UserId} from IP {ClientIP}. Reason: {Reason} at {Timestamp}",
            userId ?? "Unknown", clientIp, reason, DateTime.UtcNow);
        
        await Task.CompletedTask;
    }

    public async Task LogRateLimitViolationAsync(string endpoint, string clientIp, string userAgent)
    {
        _logger.LogWarning(
            "SECURITY_AUDIT: Rate limit violation on endpoint {Endpoint} from IP {ClientIP} with UserAgent {UserAgent} at {Timestamp}",
            endpoint, clientIp, userAgent, DateTime.UtcNow);
        
        await Task.CompletedTask;
    }

    public async Task LogSecurityConfigurationIssueAsync(string issue, string severity)
    {
        if (severity.ToLowerInvariant() == "critical")
        {
            _logger.LogCritical(
                "SECURITY_AUDIT: CRITICAL security configuration issue - {Issue} at {Timestamp}",
                issue, DateTime.UtcNow);
        }
        else if (severity.ToLowerInvariant() == "high")
        {
            _logger.LogError(
                "SECURITY_AUDIT: HIGH severity security configuration issue - {Issue} at {Timestamp}",
                issue, DateTime.UtcNow);
        }
        else
        {
            _logger.LogWarning(
                "SECURITY_AUDIT: Security configuration issue - {Issue} (Severity: {Severity}) at {Timestamp}",
                issue, severity, DateTime.UtcNow);
        }
        
        await Task.CompletedTask;
    }
}