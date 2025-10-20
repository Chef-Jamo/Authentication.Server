using Auth.Service.Project.Services;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Auth.Service.Project.Tests.Services;

public class SecurityAuditServiceTests
{
    private readonly Mock<ILogger<SecurityAuditService>> _mockLogger;
    private readonly SecurityAuditService _securityAuditService;

    public SecurityAuditServiceTests()
    {
        _mockLogger = new Mock<ILogger<SecurityAuditService>>();
        _securityAuditService = new SecurityAuditService(_mockLogger.Object);
    }

    [Fact]
    public async Task LogSuccessfulLoginAsync_ShouldLogSuccessfulLogin()
    {
        // Arrange
        var email = "test@example.com";
        var clientIp = "192.168.1.1";
        var userAgent = "Mozilla/5.0";

        // Act
        await _securityAuditService.LogSuccessfulLoginAsync(email, clientIp, userAgent);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Successful login")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task LogFailedLoginAsync_ShouldLogFailedLogin()
    {
        // Arrange
        var email = "test@example.com";
        var clientIp = "192.168.1.1";
        var userAgent = "Mozilla/5.0";
        var reason = "Invalid password";

        // Act
        await _securityAuditService.LogFailedLoginAsync(email, clientIp, userAgent, reason);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Failed login attempt")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task LogAccountLockoutAsync_ShouldLogLockoutEvent()
    {
        // Arrange
        var email = "test@example.com";
        var clientIp = "192.168.1.1";
        var failedAttempts = 5;

        // Act
        await _securityAuditService.LogAccountLockoutAsync(email, clientIp, failedAttempts);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Account locked")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task LogPasswordChangeAsync_ShouldLogSuccessfulPasswordChange()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var email = "test@example.com";
        var clientIp = "192.168.1.1";

        // Act
        await _securityAuditService.LogPasswordChangeAsync(userId, email, clientIp, true);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Password changed successfully")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task LogPasswordChangeAsync_ShouldLogFailedPasswordChange()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var email = "test@example.com";
        var clientIp = "192.168.1.1";

        // Act
        await _securityAuditService.LogPasswordChangeAsync(userId, email, clientIp, false);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Failed password change attempt")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task LogPasswordResetRequestAsync_ShouldLogPasswordResetRequest()
    {
        // Arrange
        var email = "test@example.com";
        var clientIp = "192.168.1.1";

        // Act
        await _securityAuditService.LogPasswordResetRequestAsync(email, clientIp);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Password reset requested")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task LogSuspiciousActivityAsync_ShouldLogSuspiciousActivity()
    {
        // Arrange
        var activity = "Multiple failed login attempts";
        var clientIp = "192.168.1.1";
        var userAgent = "Mozilla/5.0";
        var userId = "user123";

        // Act
        await _securityAuditService.LogSuspiciousActivityAsync(activity, clientIp, userAgent, userId);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Suspicious activity detected")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task LogTokenBlacklistedAsync_ShouldLogTokenBlacklisting()
    {
        // Arrange
        var userId = "user123";
        var clientIp = "192.168.1.1";
        var reason = "User logout";

        // Act
        await _securityAuditService.LogTokenBlacklistedAsync(userId, clientIp, reason);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Information,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Token blacklisted")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task LogRateLimitViolationAsync_ShouldLogRateLimitViolation()
    {
        // Arrange
        var endpoint = "/api/auth/login";
        var clientIp = "192.168.1.1";
        var userAgent = "Mozilla/5.0";

        // Act
        await _securityAuditService.LogRateLimitViolationAsync(endpoint, clientIp, userAgent);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Rate limit violation")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Theory]
    [InlineData("critical", LogLevel.Critical)]
    [InlineData("high", LogLevel.Error)]
    [InlineData("medium", LogLevel.Warning)]
    public async Task LogSecurityConfigurationIssueAsync_ShouldLogWithCorrectSeverity(string severity, LogLevel expectedLogLevel)
    {
        // Arrange
        var issue = "Security configuration issue detected";

        // Act
        await _securityAuditService.LogSecurityConfigurationIssueAsync(issue, severity);

        // Assert
        _mockLogger.Verify(
            x => x.Log(
                expectedLogLevel,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Security configuration issue")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }
}