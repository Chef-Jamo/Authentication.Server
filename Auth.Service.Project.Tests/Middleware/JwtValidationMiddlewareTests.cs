using Auth.Service.Project.Middleware;
using Auth.Service.Project.Services;
using FluentAssertions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;

namespace Auth.Service.Project.Tests.Middleware;

public class JwtValidationMiddlewareTests
{
    private readonly Mock<RequestDelegate> _mockNext;
    private readonly Mock<ILogger<JwtValidationMiddleware>> _mockLogger;
    private readonly Mock<IJwtBlacklistService> _mockBlacklistService;
    private readonly JwtValidationMiddleware _middleware;

    public JwtValidationMiddlewareTests()
    {
        _mockNext = new Mock<RequestDelegate>();
        _mockLogger = new Mock<ILogger<JwtValidationMiddleware>>();
        _mockBlacklistService = new Mock<IJwtBlacklistService>();
        
        _middleware = new JwtValidationMiddleware(_mockNext.Object, _mockLogger.Object);
    }

    [Fact]
    public async Task InvokeAsync_ShouldCallNext_WhenNoAuthorizeAttribute()
    {
        // Arrange
        var context = CreateHttpContext();
        // Don't set any authorization metadata

        // Act
        await _middleware.InvokeAsync(context, _mockBlacklistService.Object);

        // Assert
        _mockNext.Verify(x => x(context), Times.Once);
        _mockBlacklistService.Verify(x => x.IsTokenBlacklistedAsync(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task InvokeAsync_ShouldCallNext_WhenNoToken()
    {
        // Arrange
        var context = CreateHttpContext();
        SetAuthorizationRequired(context);

        // Act
        await _middleware.InvokeAsync(context, _mockBlacklistService.Object);

        // Assert
        _mockNext.Verify(x => x(context), Times.Once);
        _mockBlacklistService.Verify(x => x.IsTokenBlacklistedAsync(It.IsAny<string>()), Times.Never);
    }

    [Fact]
    public async Task InvokeAsync_ShouldReturn401_WhenTokenIsBlacklisted()
    {
        // Arrange
        var context = CreateHttpContext();
        SetAuthorizationRequired(context);
        SetAuthorizationHeader(context, "Bearer valid-token");
        
        _mockBlacklistService.Setup(x => x.IsTokenBlacklistedAsync("valid-token"))
            .ReturnsAsync(true);

        // Act
        await _middleware.InvokeAsync(context, _mockBlacklistService.Object);

        // Assert
        context.Response.StatusCode.Should().Be(401);
        _mockNext.Verify(x => x(context), Times.Never);
        
        // Verify logging
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Blocked request with blacklisted token")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task InvokeAsync_ShouldCallNext_WhenTokenIsNotBlacklisted()
    {
        // Arrange
        var context = CreateHttpContext();
        SetAuthorizationRequired(context);
        SetAuthorizationHeader(context, "Bearer valid-token");
        
        _mockBlacklistService.Setup(x => x.IsTokenBlacklistedAsync("valid-token"))
            .ReturnsAsync(false);

        // Act
        await _middleware.InvokeAsync(context, _mockBlacklistService.Object);

        // Assert
        _mockNext.Verify(x => x(context), Times.Once);
        context.Response.StatusCode.Should().Be(200);
    }

    [Fact]
    public async Task InvokeAsync_ShouldContinue_WhenBlacklistCheckFails()
    {
        // Arrange
        var context = CreateHttpContext();
        SetAuthorizationRequired(context);
        SetAuthorizationHeader(context, "Bearer valid-token");
        
        _mockBlacklistService.Setup(x => x.IsTokenBlacklistedAsync("valid-token"))
            .ThrowsAsync(new InvalidOperationException("Blacklist check failed"));

        // Act
        await _middleware.InvokeAsync(context, _mockBlacklistService.Object);

        // Assert
        _mockNext.Verify(x => x(context), Times.Once);
        
        // Verify error logging
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Error,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Error checking token blacklist")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Theory]
    [InlineData("Bearer token123", "token123")]
    [InlineData("bearer token456", "token456")]
    [InlineData("BEARER token789", "token789")]
    public async Task InvokeAsync_ShouldExtractToken_FromAuthorizationHeader(string headerValue, string expectedToken)
    {
        // Arrange
        var context = CreateHttpContext();
        SetAuthorizationRequired(context);
        SetAuthorizationHeader(context, headerValue);
        
        _mockBlacklistService.Setup(x => x.IsTokenBlacklistedAsync(expectedToken))
            .ReturnsAsync(false);

        // Act
        await _middleware.InvokeAsync(context, _mockBlacklistService.Object);

        // Assert
        _mockBlacklistService.Verify(x => x.IsTokenBlacklistedAsync(expectedToken), Times.Once);
        _mockNext.Verify(x => x(context), Times.Once);
    }

    private static DefaultHttpContext CreateHttpContext()
    {
        var context = new DefaultHttpContext();
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static void SetAuthorizationRequired(HttpContext context)
    {
        var endpoint = new Endpoint(
            requestDelegate: (_) => Task.CompletedTask,
            metadata: new EndpointMetadataCollection(new AuthorizeAttribute()),
            displayName: "Test");
        
        context.SetEndpoint(endpoint);
    }

    private static void SetAuthorizationHeader(HttpContext context, string value)
    {
        context.Request.Headers.Authorization = value;
    }
}