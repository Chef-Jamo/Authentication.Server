using System.Security.Claims;
using System.Text;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Moq;
using Auth.Service.Project.Controllers;
using Auth.Service.Project.DTOs;
using Auth.Service.Project.Services;
using Xunit;

namespace Auth.Service.Project.Tests.Controllers;

public class AuthControllerTests
{
    private readonly Mock<IAuthService> _mockAuthService;
    private readonly Mock<ILogger<AuthController>> _mockLogger;
    private readonly AuthController _controller;
    
    public AuthControllerTests()
    {
        _mockAuthService = new Mock<IAuthService>();
        _mockLogger = new Mock<ILogger<AuthController>>();
        _controller = new AuthController(_mockAuthService.Object, _mockLogger.Object);
    }
    
    [Fact]
    public async Task Register_ShouldReturnOk_WhenValidRequest()
    {
        // Arrange
        var request = new RegisterRequestDto
        {
            Email = "test@example.com",
            Password = "Password123!",
            FirstName = "Test",
            LastName = "User"
        };
        
        var expectedResponse = ApiResponseDto<UserDto>.SuccessResponse(
            new UserDto
            {
                Id = Guid.NewGuid(),
                Email = "test@example.com",
                FirstName = "Test",
                LastName = "User",
                FullName = "Test User",
                IsEmailVerified = false,
                CreatedAt = DateTime.UtcNow
            },
            "Registration successful"
        );
        
        _mockAuthService.Setup(x => x.RegisterAsync(request))
            .ReturnsAsync(expectedResponse);
        
        // Act
        var result = await _controller.Register(request);
        
        // Assert
        result.Should().BeOfType<ActionResult<ApiResponseDto<UserDto>>>();
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value.Should().BeOfType<ApiResponseDto<UserDto>>().Subject;
        
        response.Success.Should().BeTrue();
        response.Data!.Email.Should().Be("test@example.com");
    }
    
    [Fact]
    public async Task Register_ShouldReturnBadRequest_WhenRegistrationFails()
    {
        // Arrange
        var request = new RegisterRequestDto
        {
            Email = "test@example.com",
            Password = "Password123!",
            FirstName = "Test",
            LastName = "User"
        };
        
        var expectedResponse = ApiResponseDto<UserDto>.ErrorResponse("User with this email already exists");
        
        _mockAuthService.Setup(x => x.RegisterAsync(request))
            .ReturnsAsync(expectedResponse);
        
        // Act
        var result = await _controller.Register(request);
        
        // Assert
        var badRequestResult = result.Result.Should().BeOfType<BadRequestObjectResult>().Subject;
        var response = badRequestResult.Value.Should().BeOfType<ApiResponseDto<UserDto>>().Subject;
        
        response.Success.Should().BeFalse();
        response.Message.Should().Be("User with this email already exists");
    }
    
    [Fact]
    public async Task Login_ShouldReturnOk_WhenValidCredentials()
    {
        // Arrange
        var request = new LoginRequestDto
        {
            Email = "test@example.com",
            Password = "Password123!"
        };
        
        var expectedResponse = ApiResponseDto<LoginResponseDto>.SuccessResponse(
            new LoginResponseDto
            {
                Token = "jwt-token",
                RefreshToken = "refresh-token",
                ExpiresAt = DateTime.UtcNow.AddHours(1),
                User = new UserDto
                {
                    Id = Guid.NewGuid(),
                    Email = "test@example.com",
                    FirstName = "Test",
                    LastName = "User",
                    FullName = "Test User",
                    IsEmailVerified = true,
                    CreatedAt = DateTime.UtcNow
                }
            },
            "Login successful"
        );
        
        _mockAuthService.Setup(x => x.LoginAsync(request))
            .ReturnsAsync(expectedResponse);
        
        // Act
        var result = await _controller.Login(request);
        
        // Assert
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value.Should().BeOfType<ApiResponseDto<LoginResponseDto>>().Subject;
        
        response.Success.Should().BeTrue();
        response.Data!.Token.Should().Be("jwt-token");
        response.Data.RefreshToken.Should().Be("refresh-token");
    }
    
    [Fact]
    public async Task Login_ShouldReturnBadRequest_WhenInvalidCredentials()
    {
        // Arrange
        var request = new LoginRequestDto
        {
            Email = "test@example.com",
            Password = "WrongPassword"
        };
        
        var expectedResponse = ApiResponseDto<LoginResponseDto>.ErrorResponse("Invalid email or password");
        
        _mockAuthService.Setup(x => x.LoginAsync(request))
            .ReturnsAsync(expectedResponse);
        
        // Act
        var result = await _controller.Login(request);
        
        // Assert
        var badRequestResult = result.Result.Should().BeOfType<BadRequestObjectResult>().Subject;
        var response = badRequestResult.Value.Should().BeOfType<ApiResponseDto<LoginResponseDto>>().Subject;
        
        response.Success.Should().BeFalse();
        response.Message.Should().Be("Invalid email or password");
    }
    
    [Fact]
    public async Task ForgotPassword_ShouldReturnOk_Always()
    {
        // Arrange
        var request = new PasswordResetRequestDto
        {
            Email = "test@example.com"
        };
        
        var expectedResponse = ApiResponseDto<string>.SuccessResponse(
            "If an account with that email exists, a password reset link has been sent."
        );
        
        _mockAuthService.Setup(x => x.RequestPasswordResetAsync(request))
            .ReturnsAsync(expectedResponse);
        
        // Act
        var result = await _controller.ForgotPassword(request);
        
        // Assert
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value.Should().BeOfType<ApiResponseDto<string>>().Subject;
        
        response.Success.Should().BeTrue();
        response.Data.Should().Be("If an account with that email exists, a password reset link has been sent.");
    }
    
    [Fact]
    public async Task ResetPassword_ShouldReturnOk_WhenValidToken()
    {
        // Arrange
        var request = new PasswordResetDto
        {
            Token = "valid-token",
            NewPassword = "NewPassword123!"
        };
        
        var expectedResponse = ApiResponseDto<string>.SuccessResponse("Password has been reset successfully");
        
        _mockAuthService.Setup(x => x.ResetPasswordAsync(request))
            .ReturnsAsync(expectedResponse);
        
        // Act
        var result = await _controller.ResetPassword(request);
        
        // Assert
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value.Should().BeOfType<ApiResponseDto<string>>().Subject;
        
        response.Success.Should().BeTrue();
        response.Data.Should().Be("Password has been reset successfully");
    }
    
    [Fact]
    public async Task ResetPassword_ShouldReturnBadRequest_WhenInvalidToken()
    {
        // Arrange
        var request = new PasswordResetDto
        {
            Token = "invalid-token",
            NewPassword = "NewPassword123!"
        };
        
        var expectedResponse = ApiResponseDto<string>.ErrorResponse("Invalid or expired reset token");
        
        _mockAuthService.Setup(x => x.ResetPasswordAsync(request))
            .ReturnsAsync(expectedResponse);
        
        // Act
        var result = await _controller.ResetPassword(request);
        
        // Assert
        var badRequestResult = result.Result.Should().BeOfType<BadRequestObjectResult>().Subject;
        var response = badRequestResult.Value.Should().BeOfType<ApiResponseDto<string>>().Subject;
        
        response.Success.Should().BeFalse();
        response.Message.Should().Be("Invalid or expired reset token");
    }
    
    [Fact]
    public async Task ChangePassword_ShouldReturnOk_WhenValidRequest()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var request = new ChangePasswordDto
        {
            CurrentPassword = "CurrentPassword123!",
            NewPassword = "NewPassword123!"
        };
        
        // Setup the user claims
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId.ToString()),
            new(ClaimTypes.Email, "test@example.com")
        };
        
        var identity = new ClaimsIdentity(claims, "Test");
        var claimsPrincipal = new ClaimsPrincipal(identity);
        
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = claimsPrincipal
            }
        };
        
        var expectedResponse = ApiResponseDto<string>.SuccessResponse("Password has been changed successfully");
        
        _mockAuthService.Setup(x => x.ChangePasswordAsync(userId, request))
            .ReturnsAsync(expectedResponse);
        
        // Act
        var result = await _controller.ChangePassword(request);
        
        // Assert
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value.Should().BeOfType<ApiResponseDto<string>>().Subject;
        
        response.Success.Should().BeTrue();
        response.Data.Should().Be("Password has been changed successfully");
    }
    
    [Fact]
    public async Task ChangePassword_ShouldReturnUnauthorized_WhenNoUserIdClaim()
    {
        // Arrange
        var request = new ChangePasswordDto
        {
            CurrentPassword = "CurrentPassword123!",
            NewPassword = "NewPassword123!"
        };
        
        // Setup controller without user claims
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal()
            }
        };
        
        // Act
        var result = await _controller.ChangePassword(request);
        
        // Assert
        var unauthorizedResult = result.Result.Should().BeOfType<UnauthorizedObjectResult>().Subject;
        var response = unauthorizedResult.Value.Should().BeOfType<ApiResponseDto<string>>().Subject;
        
        response.Success.Should().BeFalse();
        response.Message.Should().Be("Invalid user token");
    }
    
    [Fact]
    public async Task VerifyEmail_ShouldReturnOk_WhenValidToken()
    {
        // Arrange
        var token = "valid-verification-token";
        var expectedResponse = ApiResponseDto<string>.SuccessResponse("Email has been verified successfully");
        
        _mockAuthService.Setup(x => x.VerifyEmailAsync(token))
            .ReturnsAsync(expectedResponse);
        
        // Act
        var result = await _controller.VerifyEmail(token);
        
        // Assert
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value.Should().BeOfType<ApiResponseDto<string>>().Subject;
        
        response.Success.Should().BeTrue();
        response.Data.Should().Be("Email has been verified successfully");
    }
    
    [Fact]
    public async Task VerifyEmail_ShouldReturnBadRequest_WhenTokenIsEmpty()
    {
        // Act
        var result = await _controller.VerifyEmail("");
        
        // Assert
        var badRequestResult = result.Result.Should().BeOfType<BadRequestObjectResult>().Subject;
        var response = badRequestResult.Value.Should().BeOfType<ApiResponseDto<string>>().Subject;
        
        response.Success.Should().BeFalse();
        response.Message.Should().Be("Verification token is required");
    }
    
    [Fact]
    public async Task RefreshToken_ShouldReturnOk_WhenValidRefreshToken()
    {
        // Arrange
        var request = new RefreshTokenRequestDto
        {
            RefreshToken = "valid-refresh-token"
        };
        
        var expectedResponse = ApiResponseDto<LoginResponseDto>.SuccessResponse(
            new LoginResponseDto
            {
                Token = "new-jwt-token",
                RefreshToken = "new-refresh-token",
                ExpiresAt = DateTime.UtcNow.AddHours(1),
                User = new UserDto
                {
                    Id = Guid.NewGuid(),
                    Email = "test@example.com",
                    FirstName = "Test",
                    LastName = "User",
                    FullName = "Test User",
                    IsEmailVerified = true,
                    CreatedAt = DateTime.UtcNow
                }
            },
            "Token refreshed successfully"
        );
        
        _mockAuthService.Setup(x => x.RefreshTokenAsync("valid-refresh-token"))
            .ReturnsAsync(expectedResponse);
        
        // Act
        var result = await _controller.RefreshToken(request);
        
        // Assert
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value.Should().BeOfType<ApiResponseDto<LoginResponseDto>>().Subject;
        
        response.Success.Should().BeTrue();
        response.Data!.Token.Should().Be("new-jwt-token");
        response.Data.RefreshToken.Should().Be("new-refresh-token");
    }
    
    [Fact]
    public async Task RefreshToken_ShouldReturnBadRequest_WhenRefreshTokenIsEmpty()
    {
        // Arrange
        var request = new RefreshTokenRequestDto
        {
            RefreshToken = ""
        };
        
        // Act
        var result = await _controller.RefreshToken(request);
        
        // Assert
        var badRequestResult = result.Result.Should().BeOfType<BadRequestObjectResult>().Subject;
        var response = badRequestResult.Value.Should().BeOfType<ApiResponseDto<LoginResponseDto>>().Subject;
        
        response.Success.Should().BeFalse();
        response.Message.Should().Be("Refresh token is required");
    }
    
    [Fact]
    public async Task Logout_ShouldReturnOk()
    {
        // Arrange
        var expectedResponse = ApiResponseDto<string>.SuccessResponse("Logged out successfully");
        
        _mockAuthService.Setup(x => x.LogoutAsync(It.IsAny<string>()))
            .ReturnsAsync(expectedResponse);
        
        // Setup authorization header
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext()
        };
        _controller.Request.Headers.Authorization = "Bearer jwt-token";
        
        // Act
        var result = await _controller.Logout();
        
        // Assert
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value.Should().BeOfType<ApiResponseDto<string>>().Subject;
        
        response.Success.Should().BeTrue();
        response.Data.Should().Be("Logged out successfully");
    }
    
    [Fact]
    public void GetProfile_ShouldReturnOk_WhenAuthenticatedUser()
    {
        // Arrange
        var userId = Guid.NewGuid();
        var email = "test@example.com";
        
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId.ToString()),
            new(ClaimTypes.Email, email)
        };
        
        var identity = new ClaimsIdentity(claims, "Test");
        var claimsPrincipal = new ClaimsPrincipal(identity);
        
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = claimsPrincipal
            }
        };
        
        // Act
        var result = _controller.GetProfile();
        
        // Assert
        var okResult = result.Result.Should().BeOfType<OkObjectResult>().Subject;
        var response = okResult.Value.Should().BeOfType<ApiResponseDto<object>>().Subject;
        
        response.Success.Should().BeTrue();
        response.Message.Should().Be("Profile retrieved successfully");
        
        response.Data.Should().NotBeNull();
    }
    
    [Fact]
    public void GetProfile_ShouldReturnUnauthorized_WhenNoUserClaims()
    {
        // Arrange
        _controller.ControllerContext = new ControllerContext
        {
            HttpContext = new DefaultHttpContext
            {
                User = new ClaimsPrincipal()
            }
        };
        
        // Act
        var result = _controller.GetProfile();
        
        // Assert
        var unauthorizedResult = result.Result.Should().BeOfType<UnauthorizedObjectResult>().Subject;
        var response = unauthorizedResult.Value.Should().BeOfType<ApiResponseDto<object>>().Subject;
        
        response.Success.Should().BeFalse();
        response.Message.Should().Be("Invalid user token");
    }
}