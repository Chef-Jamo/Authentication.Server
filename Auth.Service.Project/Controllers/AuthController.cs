using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Auth.Service.Project.DTOs;
using Auth.Service.Project.Services;

namespace Auth.Service.Project.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;
    private readonly ILogger<AuthController> _logger;
    
    public AuthController(IAuthService authService, ILogger<AuthController> logger)
    {
        _authService = authService;
        _logger = logger;
    }
    
    /// <summary>
    /// Register a new user account
    /// </summary>
    [HttpPost("register")]
    public async Task<ActionResult<ApiResponseDto<UserDto>>> Register([FromBody] RegisterRequestDto request)
    {
        if (!ModelState.IsValid)
        {
            var errors = ModelState
                .Where(x => x.Value?.Errors.Count > 0)
                .ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value?.Errors.Select(e => e.ErrorMessage).ToArray() ?? Array.Empty<string>()
                );
            
            return BadRequest(ApiResponseDto<UserDto>.ErrorResponse("Validation failed", errors));
        }
        
        var result = await _authService.RegisterAsync(request);
        
        if (!result.Success)
        {
            return BadRequest(result);
        }
        
        return Ok(result);
    }
    
    /// <summary>
    /// Login with email and password
    /// </summary>
    [HttpPost("login")]
    public async Task<ActionResult<ApiResponseDto<LoginResponseDto>>> Login([FromBody] LoginRequestDto request)
    {
        if (!ModelState.IsValid)
        {
            var errors = ModelState
                .Where(x => x.Value?.Errors.Count > 0)
                .ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value?.Errors.Select(e => e.ErrorMessage).ToArray() ?? Array.Empty<string>()
                );
            
            return BadRequest(ApiResponseDto<LoginResponseDto>.ErrorResponse("Validation failed", errors));
        }
        
        var result = await _authService.LoginAsync(request);
        
        if (!result.Success)
        {
            return BadRequest(result);
        }
        
        return Ok(result);
    }
    
    /// <summary>
    /// Request a password reset link
    /// </summary>
    [HttpPost("forgot-password")]
    public async Task<ActionResult<ApiResponseDto<string>>> ForgotPassword([FromBody] PasswordResetRequestDto request)
    {
        if (!ModelState.IsValid)
        {
            var errors = ModelState
                .Where(x => x.Value?.Errors.Count > 0)
                .ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value?.Errors.Select(e => e.ErrorMessage).ToArray() ?? Array.Empty<string>()
                );
            
            return BadRequest(ApiResponseDto<string>.ErrorResponse("Validation failed", errors));
        }
        
        var result = await _authService.RequestPasswordResetAsync(request);
        return Ok(result);
    }
    
    /// <summary>
    /// Reset password using a reset token
    /// </summary>
    [HttpPost("reset-password")]
    public async Task<ActionResult<ApiResponseDto<string>>> ResetPassword([FromBody] PasswordResetDto request)
    {
        if (!ModelState.IsValid)
        {
            var errors = ModelState
                .Where(x => x.Value?.Errors.Count > 0)
                .ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value?.Errors.Select(e => e.ErrorMessage).ToArray() ?? Array.Empty<string>()
                );
            
            return BadRequest(ApiResponseDto<string>.ErrorResponse("Validation failed", errors));
        }
        
        var result = await _authService.ResetPasswordAsync(request);
        
        if (!result.Success)
        {
            return BadRequest(result);
        }
        
        return Ok(result);
    }
    
    /// <summary>
    /// Change password for authenticated user
    /// </summary>
    [HttpPost("change-password")]
    [Authorize]
    public async Task<ActionResult<ApiResponseDto<string>>> ChangePassword([FromBody] ChangePasswordDto request)
    {
        if (!ModelState.IsValid)
        {
            var errors = ModelState
                .Where(x => x.Value?.Errors.Count > 0)
                .ToDictionary(
                    kvp => kvp.Key,
                    kvp => kvp.Value?.Errors.Select(e => e.ErrorMessage).ToArray() ?? Array.Empty<string>()
                );
            
            return BadRequest(ApiResponseDto<string>.ErrorResponse("Validation failed", errors));
        }
        
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);
        
        if (userIdClaim == null || !Guid.TryParse(userIdClaim.Value, out var userId))
        {
            return Unauthorized(ApiResponseDto<string>.ErrorResponse("Invalid user token"));
        }
        
        var result = await _authService.ChangePasswordAsync(userId, request);
        
        if (!result.Success)
        {
            return BadRequest(result);
        }
        
        return Ok(result);
    }
    
    /// <summary>
    /// Verify email address using verification token
    /// </summary>
    [HttpPost("verify-email")]
    public async Task<ActionResult<ApiResponseDto<string>>> VerifyEmail([FromQuery] string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return BadRequest(ApiResponseDto<string>.ErrorResponse("Verification token is required"));
        }
        
        var result = await _authService.VerifyEmailAsync(token);
        
        if (!result.Success)
        {
            return BadRequest(result);
        }
        
        return Ok(result);
    }
    
    /// <summary>
    /// Refresh JWT token using refresh token
    /// </summary>
    [HttpPost("refresh")]
    public async Task<ActionResult<ApiResponseDto<LoginResponseDto>>> RefreshToken([FromBody] RefreshTokenRequestDto request)
    {
        if (string.IsNullOrWhiteSpace(request.RefreshToken))
        {
            return BadRequest(ApiResponseDto<LoginResponseDto>.ErrorResponse("Refresh token is required"));
        }
        
        var result = await _authService.RefreshTokenAsync(request.RefreshToken);
        
        if (!result.Success)
        {
            return BadRequest(result);
        }
        
        return Ok(result);
    }
    
    /// <summary>
    /// Logout user
    /// </summary>
    [HttpPost("logout")]
    [Authorize]
    public async Task<ActionResult<ApiResponseDto<string>>> Logout()
    {
        var token = Request.Headers.Authorization.ToString().Replace("Bearer ", "");
        var result = await _authService.LogoutAsync(token);
        return Ok(result);
    }
    
    /// <summary>
    /// Get current user profile
    /// </summary>
    [HttpGet("profile")]
    [Authorize]
    public ActionResult<ApiResponseDto<object>> GetProfile()
    {
        var userIdClaim = User.FindFirst(ClaimTypes.NameIdentifier);
        var emailClaim = User.FindFirst(ClaimTypes.Email);
        
        if (userIdClaim == null || emailClaim == null)
        {
            return Unauthorized(ApiResponseDto<object>.ErrorResponse("Invalid user token"));
        }
        
        var profile = new
        {
            Id = userIdClaim.Value,
            Email = emailClaim.Value
        };
        
        return Ok(ApiResponseDto<object>.SuccessResponse(profile, "Profile retrieved successfully"));
    }
}

public record RefreshTokenRequestDto
{
    public string RefreshToken { get; init; } = string.Empty;
}