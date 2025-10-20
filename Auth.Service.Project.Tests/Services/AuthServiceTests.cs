using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Moq;
using Auth.Service.Project.DTOs;
using Auth.Service.Project.Models;
using Auth.Service.Project.Repositories;
using Auth.Service.Project.Services;
using Auth.Service.Project.Validators;
using Xunit;

namespace Auth.Service.Project.Tests.Services;

public class AuthServiceTests
{
    private readonly Mock<IUserRepository> _mockUserRepository;
    private readonly Mock<ITokenService> _mockTokenService;
    private readonly Mock<IPasswordSecurityService> _mockPasswordSecurityService;
    private readonly Mock<IJwtBlacklistService> _mockJwtBlacklistService;
    private readonly Mock<ILogger<AuthService>> _mockLogger;
    private readonly Mock<IConfiguration> _mockConfiguration;
    private readonly AuthService _authService;
    
    public AuthServiceTests()
    {
        _mockUserRepository = new Mock<IUserRepository>();
        _mockTokenService = new Mock<ITokenService>();
        _mockPasswordSecurityService = new Mock<IPasswordSecurityService>();
        _mockJwtBlacklistService = new Mock<IJwtBlacklistService>();
        _mockLogger = new Mock<ILogger<AuthService>>();
        _mockConfiguration = new Mock<IConfiguration>();
        
        _authService = new AuthService(
            _mockUserRepository.Object,
            _mockTokenService.Object,
            _mockPasswordSecurityService.Object,
            _mockJwtBlacklistService.Object,
            _mockLogger.Object,
            _mockConfiguration.Object);
    }
    
    [Fact]
    public async Task RegisterAsync_ShouldReturnSuccess_WhenValidRequest()
    {
        // Arrange
        var registerRequest = new RegisterRequestDto
        {
            Email = "test@example.com",
            Password = "ValidStrongP@ssw0rd123!",
            FirstName = "Test",
            LastName = "User"
        };
        
        _mockUserRepository.Setup(x => x.ExistsAsync(It.IsAny<string>()))
            .ReturnsAsync(false);
        
        _mockUserRepository.Setup(x => x.CreateAsync(It.IsAny<User>()))
            .ReturnsAsync((User user) => user);
        
        // Setup password security service to return valid password
        _mockPasswordSecurityService.Setup(x => x.ValidatePasswordStrengthAsync(
            It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync((true, new string[0]));
        
        _mockPasswordSecurityService.Setup(x => x.StorePasswordHistoryAsync(
            It.IsAny<Guid>(), It.IsAny<string>()))
            .Returns(Task.CompletedTask);
        
        // Act
        var result = await _authService.RegisterAsync(registerRequest);
        
        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.Email.Should().Be("test@example.com");
        result.Data.FirstName.Should().Be("Test");
        result.Data.LastName.Should().Be("User");
        
        _mockUserRepository.Verify(x => x.CreateAsync(It.Is<User>(u => 
            u.Email == "test@example.com" && 
            u.FirstName == "Test" && 
            u.LastName == "User" &&
            u.EmailVerificationToken != null)), Times.Once);
        
        _mockPasswordSecurityService.Verify(x => x.ValidatePasswordStrengthAsync(
            "ValidStrongP@ssw0rd123!", "test@example.com"), Times.Once);
        _mockPasswordSecurityService.Verify(x => x.StorePasswordHistoryAsync(
            It.IsAny<Guid>(), It.IsAny<string>()), Times.Once);
    }
    
    [Fact]
    public async Task RegisterAsync_ShouldReturnError_WhenUserAlreadyExists()
    {
        // Arrange
        var registerRequest = new RegisterRequestDto
        {
            Email = "test@example.com",
            Password = "ValidStrongP@ssw0rd123!",
            FirstName = "Test",
            LastName = "User"
        };
        
        _mockUserRepository.Setup(x => x.ExistsAsync("test@example.com"))
            .ReturnsAsync(true);
        
        // Act
        var result = await _authService.RegisterAsync(registerRequest);
        
        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("User with this email already exists");
        
        _mockUserRepository.Verify(x => x.CreateAsync(It.IsAny<User>()), Times.Never);
    }
    
    [Fact]
    public async Task RegisterAsync_ShouldReturnError_WhenPasswordTooWeak()
    {
        // Arrange
        var registerRequest = new RegisterRequestDto
        {
            Email = "test@example.com",
            Password = "weak",
            FirstName = "Test",
            LastName = "User"
        };
        
        _mockUserRepository.Setup(x => x.ExistsAsync(It.IsAny<string>()))
            .ReturnsAsync(false);
        
        // Setup password security service to return invalid password
        _mockPasswordSecurityService.Setup(x => x.ValidatePasswordStrengthAsync(
            It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync((false, new[] { "Password must be at least 12 characters long" }));
        
        // Act
        var result = await _authService.RegisterAsync(registerRequest);
        
        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Password does not meet security requirements");
        result.Errors.Should().ContainKey("Password");
        result.Errors!["Password"].Should().Contain("Password must be at least 12 characters long");
        
        _mockUserRepository.Verify(x => x.CreateAsync(It.IsAny<User>()), Times.Never);
    }
    
    [Fact]
    public async Task LoginAsync_ShouldReturnSuccess_WhenValidCredentials()
    {
        // Arrange
        var loginRequest = new LoginRequestDto
        {
            Email = "test@example.com",
            Password = "Password123!"
        };
        
        var user = new User
        {
            Id = Guid.NewGuid(),
            Email = "test@example.com",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("Password123!"),
            FirstName = "Test",
            LastName = "User"
        };
        
        _mockUserRepository.Setup(x => x.GetByEmailAsync("test@example.com"))
            .ReturnsAsync(user);
        
        _mockUserRepository.Setup(x => x.IsAccountLockedAsync("test@example.com"))
            .ReturnsAsync(false);
        
        _mockUserRepository.Setup(x => x.UpdateAsync(It.IsAny<User>()))
            .ReturnsAsync((User u) => u);
        
        _mockTokenService.Setup(x => x.GenerateJwtToken(user.Id, user.Email))
            .Returns("jwt-token");
        
        _mockTokenService.Setup(x => x.GenerateRefreshToken())
            .Returns("refresh-token");
        
        _mockTokenService.Setup(x => x.GetTokenExpiry("jwt-token"))
            .Returns(DateTime.UtcNow.AddHours(1));
        
        // Act
        var result = await _authService.LoginAsync(loginRequest);
        
        // Assert
        result.Success.Should().BeTrue();
        result.Data.Should().NotBeNull();
        result.Data!.Token.Should().Be("jwt-token");
        result.Data.RefreshToken.Should().Be("refresh-token");
        result.Data.User.Email.Should().Be("test@example.com");
        
        _mockUserRepository.Verify(x => x.ResetFailedLoginAttemptsAsync("test@example.com"), Times.Once);
    }
    
    [Fact]
    public async Task LoginAsync_ShouldReturnError_WhenUserNotFound()
    {
        // Arrange
        var loginRequest = new LoginRequestDto
        {
            Email = "test@example.com",
            Password = "Password123!"
        };
        
        _mockUserRepository.Setup(x => x.GetByEmailAsync("test@example.com"))
            .ReturnsAsync((User?)null);
        
        // Act
        var result = await _authService.LoginAsync(loginRequest);
        
        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Invalid email or password");
    }
    
    [Fact]
    public async Task LoginAsync_ShouldReturnError_WhenAccountIsLocked()
    {
        // Arrange
        var loginRequest = new LoginRequestDto
        {
            Email = "test@example.com",
            Password = "Password123!"
        };
        
        var user = new User
        {
            Email = "test@example.com",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("Password123!"),
            FirstName = "Test",
            LastName = "User"
        };
        
        _mockUserRepository.Setup(x => x.GetByEmailAsync("test@example.com"))
            .ReturnsAsync(user);
        
        _mockUserRepository.Setup(x => x.IsAccountLockedAsync("test@example.com"))
            .ReturnsAsync(true);
        
        // Act
        var result = await _authService.LoginAsync(loginRequest);
        
        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Account is temporarily locked due to too many failed attempts");
    }
    
    [Fact]
    public async Task LoginAsync_ShouldIncrementFailedAttempts_WhenInvalidPassword()
    {
        // Arrange
        var loginRequest = new LoginRequestDto
        {
            Email = "test@example.com",
            Password = "WrongPassword"
        };
        
        var user = new User
        {
            Email = "test@example.com",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("CorrectPassword"),
            FirstName = "Test",
            LastName = "User"
        };
        
        _mockUserRepository.Setup(x => x.GetByEmailAsync("test@example.com"))
            .ReturnsAsync(user);
        
        _mockUserRepository.Setup(x => x.IsAccountLockedAsync("test@example.com"))
            .ReturnsAsync(false);
        
        _mockUserRepository.Setup(x => x.GetFailedLoginAttemptsAsync("test@example.com"))
            .ReturnsAsync(3);
        
        // Act
        var result = await _authService.LoginAsync(loginRequest);
        
        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Invalid email or password");
        
        _mockUserRepository.Verify(x => x.IncrementFailedLoginAttemptsAsync("test@example.com"), Times.Once);
    }
    
    [Theory]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(10)]
    public async Task LoginAsync_ShouldLockAccount_WhenMaxFailedAttemptsReached(int failedAttempts)
    {
        // Arrange
        var loginRequest = new LoginRequestDto
        {
            Email = "test@example.com",
            Password = "WrongPassword"
        };
        
        var user = new User
        {
            Email = "test@example.com",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("CorrectPassword"),
            FirstName = "Test",
            LastName = "User"
        };
        
        _mockUserRepository.Setup(x => x.GetByEmailAsync("test@example.com"))
            .ReturnsAsync(user);
        
        _mockUserRepository.Setup(x => x.IsAccountLockedAsync("test@example.com"))
            .ReturnsAsync(false);
        
        _mockUserRepository.Setup(x => x.GetFailedLoginAttemptsAsync("test@example.com"))
            .ReturnsAsync(failedAttempts);
        
        // Act
        var result = await _authService.LoginAsync(loginRequest);
        
        // Assert
        result.Success.Should().BeFalse();
        
        _mockUserRepository.Verify(x => x.IncrementFailedLoginAttemptsAsync("test@example.com"), Times.Once);
        _mockUserRepository.Verify(x => x.LockAccountAsync("test@example.com", It.IsAny<DateTime>()), Times.Once);
    }
    
    [Fact]
    public async Task RequestPasswordResetAsync_ShouldReturnSuccess_WhenUserExists()
    {
        // Arrange
        var request = new PasswordResetRequestDto
        {
            Email = "test@example.com"
        };
        
        var user = new User
        {
            Email = "test@example.com",
            PasswordHash = "hashedpassword",
            FirstName = "Test",
            LastName = "User"
        };
        
        _mockUserRepository.Setup(x => x.GetByEmailAsync("test@example.com"))
            .ReturnsAsync(user);
        
        _mockUserRepository.Setup(x => x.UpdateAsync(It.IsAny<User>()))
            .ReturnsAsync((User u) => u);
        
        // Act
        var result = await _authService.RequestPasswordResetAsync(request);
        
        // Assert
        result.Success.Should().BeTrue();
        result.Message.Should().Be("If an account with that email exists, a password reset link has been sent.");
        
        _mockUserRepository.Verify(x => x.UpdateAsync(It.Is<User>(u => 
            u.PasswordResetToken != null && 
            u.PasswordResetTokenExpiry > DateTime.UtcNow)), Times.Once);
    }
    
    [Fact]
    public async Task RequestPasswordResetAsync_ShouldReturnSuccess_WhenUserDoesNotExist()
    {
        // Arrange
        var request = new PasswordResetRequestDto
        {
            Email = "nonexistent@example.com"
        };
        
        _mockUserRepository.Setup(x => x.GetByEmailAsync("nonexistent@example.com"))
            .ReturnsAsync((User?)null);
        
        // Act
        var result = await _authService.RequestPasswordResetAsync(request);
        
        // Assert
        result.Success.Should().BeTrue();
        result.Message.Should().Be("If an account with that email exists, a password reset link has been sent.");
        
        _mockUserRepository.Verify(x => x.UpdateAsync(It.IsAny<User>()), Times.Never);
    }
    
    [Fact]
    public async Task ResetPasswordAsync_ShouldReturnSuccess_WhenValidToken()
    {
        // Arrange
        var resetRequest = new PasswordResetDto
        {
            Token = "valid-token",
            NewPassword = "NewPassword123!"
        };
        
        var user = new User
        {
            Email = "test@example.com",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("OldPassword"),
            PasswordResetToken = "valid-token",
            PasswordResetTokenExpiry = DateTime.UtcNow.AddHours(1),
            FirstName = "Test",
            LastName = "User",
            FailedLoginAttempts = 3,
            IsAccountLocked = true
        };
        
        _mockUserRepository.Setup(x => x.GetByPasswordResetTokenAsync("valid-token"))
            .ReturnsAsync(user);
        
        _mockUserRepository.Setup(x => x.UpdateAsync(It.IsAny<User>()))
            .ReturnsAsync((User u) => u);
        
        // Setup password security service for new password
        _mockPasswordSecurityService.Setup(x => x.ValidatePasswordStrengthAsync(
            It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync((true, new string[0]));
        
        _mockPasswordSecurityService.Setup(x => x.IsPasswordRecentlyUsedAsync(
            It.IsAny<Guid>(), It.IsAny<string>()))
            .ReturnsAsync(false);
        
        _mockPasswordSecurityService.Setup(x => x.StorePasswordHistoryAsync(
            It.IsAny<Guid>(), It.IsAny<string>()))
            .Returns(Task.CompletedTask);
        
        // Act
        var result = await _authService.ResetPasswordAsync(resetRequest);
        
        // Assert
        result.Success.Should().BeTrue();
        result.Message.Should().Be("Password has been reset successfully");
        
        _mockUserRepository.Verify(x => x.UpdateAsync(It.Is<User>(u => 
            u.PasswordResetToken == null && 
            u.PasswordResetTokenExpiry == null &&
            u.FailedLoginAttempts == 0 &&
            u.IsAccountLocked == false &&
            u.LockedUntil == null)), Times.Once);
    }
    
    [Fact]
    public async Task ResetPasswordAsync_ShouldReturnError_WhenInvalidToken()
    {
        // Arrange
        var resetRequest = new PasswordResetDto
        {
            Token = "invalid-token",
            NewPassword = "NewPassword123!"
        };
        
        _mockUserRepository.Setup(x => x.GetByPasswordResetTokenAsync("invalid-token"))
            .ReturnsAsync((User?)null);
        
        // Act
        var result = await _authService.ResetPasswordAsync(resetRequest);
        
        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Invalid or expired reset token");
    }
    
    [Fact]
    public async Task ChangePasswordAsync_ShouldReturnSuccess_WhenValidCurrentPassword()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var changePasswordRequest = new ChangePasswordDto
        {
            CurrentPassword = "CurrentPassword123!",
            NewPassword = "NewPassword123!"
        };
        
        var user = new User
        {
            Id = userId,
            Email = "test@example.com",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("CurrentPassword123!"),
            FirstName = "Test",
            LastName = "User"
        };
        
        _mockUserRepository.Setup(x => x.GetByIdAsync(userId))
            .ReturnsAsync(user);
        
        _mockUserRepository.Setup(x => x.UpdateAsync(It.IsAny<User>()))
            .ReturnsAsync((User u) => u);
        
        // Setup password security service for new password
        _mockPasswordSecurityService.Setup(x => x.ValidatePasswordStrengthAsync(
            It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync((true, new string[0]));
        
        _mockPasswordSecurityService.Setup(x => x.IsPasswordRecentlyUsedAsync(
            It.IsAny<Guid>(), It.IsAny<string>()))
            .ReturnsAsync(false);
        
        _mockPasswordSecurityService.Setup(x => x.StorePasswordHistoryAsync(
            It.IsAny<Guid>(), It.IsAny<string>()))
            .Returns(Task.CompletedTask);
        
        // Act
        var result = await _authService.ChangePasswordAsync(userId, changePasswordRequest);
        
        // Assert
        result.Success.Should().BeTrue();
        result.Message.Should().Be("Password has been changed successfully");
        
        _mockUserRepository.Verify(x => x.UpdateAsync(It.IsAny<User>()), Times.Once);
    }
    
    [Fact]
    public async Task ChangePasswordAsync_ShouldReturnError_WhenInvalidCurrentPassword()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var changePasswordRequest = new ChangePasswordDto
        {
            CurrentPassword = "WrongPassword",
            NewPassword = "NewPassword123!"
        };
        
        var user = new User
        {
            Id = userId,
            Email = "test@example.com",
            PasswordHash = BCrypt.Net.BCrypt.HashPassword("CorrectPassword123!"),
            FirstName = "Test",
            LastName = "User"
        };
        
        _mockUserRepository.Setup(x => x.GetByIdAsync(userId))
            .ReturnsAsync(user);
        
        // Act
        var result = await _authService.ChangePasswordAsync(userId, changePasswordRequest);
        
        // Assert
        result.Success.Should().BeFalse();
        result.Message.Should().Be("Current password is incorrect");
        
        _mockUserRepository.Verify(x => x.UpdateAsync(It.IsAny<User>()), Times.Never);
    }
    
    [Fact]
    public async Task VerifyEmailAsync_ShouldReturnSuccess_WhenValidToken()
    {
        // Arrange
        var token = "valid-verification-token";
        var user = new User
        {
            Email = "test@example.com",
            EmailVerificationToken = token,
            EmailVerificationTokenExpiry = DateTime.UtcNow.AddHours(1),
            IsEmailVerified = false,
            PasswordHash = "hashedpassword",
            FirstName = "Test",
            LastName = "User"
        };
        
        _mockUserRepository.Setup(x => x.GetByEmailVerificationTokenAsync(token))
            .ReturnsAsync(user);
        
        _mockUserRepository.Setup(x => x.UpdateAsync(It.IsAny<User>()))
            .ReturnsAsync((User u) => u);
        
        // Act
        var result = await _authService.VerifyEmailAsync(token);
        
        // Assert
        result.Success.Should().BeTrue();
        result.Message.Should().Be("Email has been verified successfully");
        
        _mockUserRepository.Verify(x => x.UpdateAsync(It.Is<User>(u => 
            u.IsEmailVerified == true &&
            u.EmailVerificationToken == null &&
            u.EmailVerificationTokenExpiry == null)), Times.Once);
    }
}