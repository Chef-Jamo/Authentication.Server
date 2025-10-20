using Auth.Service.Project.Validators;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using FluentAssertions;

namespace Auth.Service.Project.Tests.Validators;

public class PasswordSecurityServiceTests
{
    private readonly Mock<ILogger<PasswordSecurityService>> _mockLogger;
    private readonly PasswordSecurityService _passwordSecurityService;

    public PasswordSecurityServiceTests()
    {
        _mockLogger = new Mock<ILogger<PasswordSecurityService>>();
        _passwordSecurityService = new PasswordSecurityService(_mockLogger.Object);
    }

    [Theory]
    [InlineData("ComplexP@ssw0rd2024", true, "Very strong password should be valid")]
    [InlineData("StrongSecurePassword123!", true, "Strong password should be valid")]
    [InlineData("password", false, "Weak password should be invalid")]
    [InlineData("PASSWORD123!", true, "Password with decent entropy should be valid")]
    [InlineData("password123!", true, "Password with decent entropy should be valid")]
    [InlineData("Password!", true, "Password with decent entropy should be valid")]
    [InlineData("Password123", false, "Password containing 'password' should be invalid")]
    [InlineData("Password123123", true, "Password with decent entropy should be valid")]
    [InlineData("Passwordabc!", true, "Password with decent entropy should be valid")]
    [InlineData("Passwordddd!", true, "Password with decent entropy should be valid")]
    [InlineData("admin", false, "Common password should be invalid")]
    [InlineData("123456", false, "Common password should be invalid")]
    public async Task ValidatePasswordStrengthAsync_ShouldValidateCorrectly(string password, bool expectedValid, string reason)
    {
        // Act
        var (isValid, errors) = await _passwordSecurityService.ValidatePasswordStrengthAsync(password, "test@example.com");

        // Assert
        isValid.Should().Be(expectedValid, reason);
        if (!expectedValid)
        {
            errors.Should().NotBeEmpty();
        }
    }

    [Fact]
    public async Task ValidatePasswordStrengthAsync_ShouldRejectPasswordWithEmailParts()
    {
        // Arrange
        const string email = "john.doe@example.com";
        const string password = "JohnPassword123!";

        // Act
        var (isValid, errors) = await _passwordSecurityService.ValidatePasswordStrengthAsync(password, email);

        // Assert
        isValid.Should().BeFalse();
        errors.Should().Contain(e => e.Contains("email address"));
    }

    [Theory]
    [InlineData("password")]
    [InlineData("123456")]  
    [InlineData("qwerty")]
    [InlineData("admin")]
    public void IsCommonPassword_ShouldDetectCommonPasswords(string password)
    {
        // Act
        var isCommon = _passwordSecurityService.IsCommonPassword(password);

        // Assert
        isCommon.Should().BeTrue($"{password} should be detected as common");
    }

    [Theory]
    [InlineData("UniqueP@ssw0rd2024")]
    [InlineData("MyStr0ng!Password")]
    public void IsCommonPassword_ShouldAllowUniquePasswords(string password)
    {
        // Act
        var isCommon = _passwordSecurityService.IsCommonPassword(password);

        // Assert
        isCommon.Should().BeFalse($"{password} should not be detected as common");
    }

    [Theory]
    [InlineData("Password123!", 60.0)] // Should have decent entropy
    [InlineData("P@ssw0rd", 45.0)] // Shorter, less entropy
    [InlineData("VeryLongAndComplexP@ssw0rd123!", 120.0)] // Very long, high entropy
    public void CalculatePasswordEntropy_ShouldCalculateCorrectly(string password, double expectedMinimumEntropy)
    {
        // Act
        var entropy = _passwordSecurityService.CalculatePasswordEntropy(password);

        // Assert
        entropy.Should().BeGreaterOrEqualTo(expectedMinimumEntropy);
    }

    [Fact]
    public async Task IsPasswordRecentlyUsedAsync_ShouldTrackPasswordHistory()
    {
        // Arrange
        var userId = Guid.NewGuid();
        const string password = "TestPassword123!";
        var hashedPassword = BCrypt.Net.BCrypt.HashPassword(password); // Create real BCrypt hash

        // Act
        await _passwordSecurityService.StorePasswordHistoryAsync(userId, hashedPassword);
        var isRecentlyUsed = await _passwordSecurityService.IsPasswordRecentlyUsedAsync(userId, password);

        // Assert - Should return true since we're checking the same password
        isRecentlyUsed.Should().BeTrue("Password should be detected as recently used");
        
        // Test with a different password
        var differentPassword = "DifferentPassword456!";
        var isDifferentPasswordUsed = await _passwordSecurityService.IsPasswordRecentlyUsedAsync(userId, differentPassword);
        isDifferentPasswordUsed.Should().BeFalse("Different password should not be detected as recently used");
    }
}

public class StrongPasswordAttributeTests
{
    private readonly StrongPasswordAttribute _attribute = new();

    [Theory]
    [InlineData("ComplexP@55w0rd!", true, "Strong password should be valid")]
    [InlineData("short", false, "Short password should be invalid")]
    [InlineData("", false, "Empty password should be invalid")]
    [InlineData("VeryLongPasswordWithNoSpecialCharacters852", false, "No special chars should be invalid")]
    [InlineData("verylongp@55w0rdwithnouppercaseandspecial!", false, "No uppercase should be invalid")]
    [InlineData("VERYLONGP@55W0RDWITHNOLOWERCASEANDSPECIAL!", false, "No lowercase should be invalid")]
    [InlineData("VeryLongSecretWithNoDigitsAndSpecial!", false, "No digits should be invalid")]
    public void IsValid_ShouldValidatePasswordsCorrectly(string? password, bool expected, string reason)
    {
        // Act
        var result = _attribute.IsValid(password);

        // Assert
        result.Should().Be(expected, reason);
    }

    [Fact]
    public void IsValid_ShouldRejectNullPassword()
    {
        // Act
        var result = _attribute.IsValid(null);

        // Assert
        result.Should().BeFalse("Null password should be invalid");
    }
}