using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Auth.Service.Project.Services;
using FluentAssertions;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Moq;
using Xunit;

namespace Auth.Service.Project.Tests.Services;

public class JwtBlacklistServiceTests
{
    private readonly Mock<IMemoryCache> _mockCache;
    private readonly Mock<ILogger<JwtBlacklistService>> _mockLogger;
    private readonly JwtBlacklistService _jwtBlacklistService;

    public JwtBlacklistServiceTests()
    {
        _mockCache = new Mock<IMemoryCache>();
        _mockLogger = new Mock<ILogger<JwtBlacklistService>>();

        // Setup the memory cache to return an ICacheEntry mock when CreateEntry is called
        var mockCacheEntry = new Mock<ICacheEntry>();
        _mockCache.Setup(x => x.CreateEntry(It.IsAny<object>()))
            .Returns(mockCacheEntry.Object);

        _jwtBlacklistService = new JwtBlacklistService(_mockCache.Object, _mockLogger.Object);
    }

    [Fact]
    public async Task BlacklistTokenAsync_ShouldAddTokenToBlacklist()
    {
        // Arrange
        var token = CreateValidJwtToken();
        object? outValue = null;
        _mockCache.Setup(x => x.TryGetValue(It.IsAny<string>(), out outValue))
            .Returns(false);

        // Act
        await _jwtBlacklistService.BlacklistTokenAsync(token);

        // Assert  
        _mockCache.Verify(x => x.CreateEntry(It.Is<object>(k => k.ToString()!.StartsWith("blacklist_"))), Times.Once);
    }

    [Fact]
    public async Task IsTokenBlacklistedAsync_ShouldReturnTrue_WhenTokenIsBlacklisted()
    {
        // Arrange
        var token = CreateValidJwtToken();
        object? outValue = true;
        _mockCache.Setup(x => x.TryGetValue(It.IsAny<string>(), out outValue))
            .Returns(true);

        // Act
        var result = await _jwtBlacklistService.IsTokenBlacklistedAsync(token);

        // Assert
        result.Should().BeTrue();
    }

    [Fact]
    public async Task IsTokenBlacklistedAsync_ShouldReturnFalse_WhenTokenIsNotBlacklisted()
    {
        // Arrange
        var token = CreateValidJwtToken();
        object? outValue = null;
        _mockCache.Setup(x => x.TryGetValue(It.IsAny<string>(), out outValue))
            .Returns(false);

        // Act
        var result = await _jwtBlacklistService.IsTokenBlacklistedAsync(token);

        // Assert
        result.Should().BeFalse();
    }

    [Fact]
    public async Task BlacklistAllUserTokensAsync_ShouldBlacklistAllTokensForUser()
    {
        // Arrange
        var userId = Guid.NewGuid();

        // Act
        await _jwtBlacklistService.BlacklistAllUserTokensAsync(userId);

        // Assert - Should not throw and should log the action
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Warning,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains($"All tokens blacklisted for user: {userId}")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    [Fact]
    public async Task CleanupExpiredTokensAsync_ShouldCompleteSuccessfully()
    {
        // Act & Assert - Should not throw
        await _jwtBlacklistService.CleanupExpiredTokensAsync();
        
        // Verify cleanup was attempted
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Debug,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString()!.Contains("Token blacklist cleanup completed")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception?, string>>()),
            Times.Once);
    }

    private static string CreateValidJwtToken()
    {
        var handler = new JwtSecurityTokenHandler();
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.NameIdentifier, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Email, "test@example.com"),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new Microsoft.IdentityModel.Tokens.SigningCredentials(
                new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(
                    System.Text.Encoding.ASCII.GetBytes("ThisIsAVeryLongSecretKeyForJWTTokenGenerationThatMustBeAtLeast32Characters")),
                Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256Signature)
        };

        var token = handler.CreateToken(tokenDescriptor);
        return handler.WriteToken(token);
    }
}