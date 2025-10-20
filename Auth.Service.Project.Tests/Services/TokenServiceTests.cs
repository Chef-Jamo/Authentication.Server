using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Auth.Service.Project.Services;
using Xunit;

namespace Auth.Service.Project.Tests.Services;

public class TokenServiceTests
{
    private readonly TokenService _tokenService;
    private readonly IConfiguration _configuration;
    
    public TokenServiceTests()
    {
        var inMemorySettings = new Dictionary<string, string> {
            {"Jwt:Secret", "ThisIsAVeryLongSecretKeyForJWTTokenGenerationThatMustBeAtLeast32Characters"},
            {"Jwt:Issuer", "Auth.Service.Project"},
            {"Jwt:Audience", "Auth.Service.Project.Client"}
        };

        _configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(inMemorySettings!)
            .Build();
            
        _tokenService = new TokenService(_configuration);
    }
    
    [Fact]
    public async Task GenerateJwtToken_ShouldReturnValidToken()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var email = "test@example.com";
        
        // Act
        var token = _tokenService.GenerateJwtToken(userId, email);
        
        // Assert
        token.Should().NotBeNullOrEmpty();
        token.Should().Contain(".");
        
        // Verify we can extract user info from token
        var userIdFromToken = await _tokenService.GetUserIdFromTokenAsync(token);
        userIdFromToken.Should().Be(userId);
    }
    
    [Fact]
    public void GenerateRefreshToken_ShouldReturnUniqueTokens()
    {
        // Act
        var token1 = _tokenService.GenerateRefreshToken();
        var token2 = _tokenService.GenerateRefreshToken();
        
        // Assert
        token1.Should().NotBeNullOrEmpty();
        token2.Should().NotBeNullOrEmpty();
        token1.Should().NotBe(token2);
    }
    
    [Fact]
    public async Task ValidateRefreshTokenAsync_ShouldReturnFalse_ForNonExistentToken()
    {
        // Arrange
        var nonExistentToken = "non-existent-token";
        
        // Act
        var result = await _tokenService.ValidateRefreshTokenAsync(nonExistentToken);
        
        // Assert
        result.Should().BeFalse();
    }
    
    [Fact]
    public async Task ValidateRefreshTokenAsync_ShouldReturnTrue_ForValidStoredToken()
    {
        // Arrange
        var refreshToken = _tokenService.GenerateRefreshToken();
        var userId = Guid.NewGuid();
        
        // Store the token (accessing internal method via reflection or cast)
        if (_tokenService is TokenService tokenService)
        {
            tokenService.StoreRefreshToken(refreshToken, userId);
        }
        
        // Act
        var result = await _tokenService.ValidateRefreshTokenAsync(refreshToken);
        
        // Assert
        result.Should().BeTrue();
    }
    
    [Fact]
    public async Task RevokeRefreshTokenAsync_ShouldInvalidateToken()
    {
        // Arrange
        var refreshToken = _tokenService.GenerateRefreshToken();
        var userId = Guid.NewGuid();
        
        if (_tokenService is TokenService tokenService)
        {
            tokenService.StoreRefreshToken(refreshToken, userId);
        }
        
        // Verify token is valid initially
        var initialValidation = await _tokenService.ValidateRefreshTokenAsync(refreshToken);
        initialValidation.Should().BeTrue();
        
        // Act
        await _tokenService.RevokeRefreshTokenAsync(refreshToken);
        
        // Assert
        var validationAfterRevoke = await _tokenService.ValidateRefreshTokenAsync(refreshToken);
        validationAfterRevoke.Should().BeFalse();
    }
    
    [Fact]
    public async Task GetUserIdFromTokenAsync_ShouldReturnCorrectUserId()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var email = "test@example.com";
        var token = _tokenService.GenerateJwtToken(userId, email);
        
        // Act
        var result = await _tokenService.GetUserIdFromTokenAsync(token);
        
        // Assert
        result.Should().Be(userId);
    }
    
    [Fact]
    public async Task GetUserIdFromTokenAsync_ShouldReturnNull_ForInvalidToken()
    {
        // Arrange
        var invalidToken = "invalid.token.here";
        
        // Act
        var result = await _tokenService.GetUserIdFromTokenAsync(invalidToken);
        
        // Assert
        result.Should().BeNull();
    }
    
    [Fact]
    public void GetTokenExpiry_ShouldReturnCorrectExpiry()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var email = "test@example.com";
        var beforeGeneration = DateTime.UtcNow;
        var token = _tokenService.GenerateJwtToken(userId, email);
        var afterGeneration = DateTime.UtcNow.AddHours(1);
        
        // Act
        var expiry = _tokenService.GetTokenExpiry(token);
        
        // Assert
        expiry.Should().BeAfter(beforeGeneration);
        expiry.Should().BeBefore(afterGeneration.AddMinutes(1)); // Allow small buffer
    }
    
    [Fact]
    public void GetTokenExpiry_ShouldReturnMinValue_ForInvalidToken()
    {
        // Arrange
        var invalidToken = "invalid.token.here";
        
        // Act
        var expiry = _tokenService.GetTokenExpiry(invalidToken);
        
        // Assert
        expiry.Should().Be(DateTime.MinValue);
    }
    
    [Theory]
    [InlineData("")]
    [InlineData(" ")]
    [InlineData("invalid")]
    [InlineData("invalid.token")]
    [InlineData("invalid.token.signature")]
    public async Task GetUserIdFromTokenAsync_ShouldReturnNull_ForVariousInvalidTokens(string invalidToken)
    {
        // Act
        var result = await _tokenService.GetUserIdFromTokenAsync(invalidToken);
        
        // Assert
        result.Should().BeNull();
    }
}