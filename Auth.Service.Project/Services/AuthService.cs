using System.Security.Cryptography;
using System.Text;
using Auth.Service.Project.DTOs;
using Auth.Service.Project.Models;
using Auth.Service.Project.Repositories;
using Auth.Service.Project.Validators;
using BCrypt.Net;

namespace Auth.Service.Project.Services;

public class AuthService : IAuthService
{
    private readonly IUserRepository _userRepository;
    private readonly ITokenService _tokenService;
    private readonly IPasswordSecurityService _passwordSecurityService;
    private readonly IJwtBlacklistService _jwtBlacklistService;
    private readonly ILogger<AuthService> _logger;
    private readonly IConfiguration _configuration;
    
    private const int MaxFailedAttempts = 5;
    private const int LockoutDurationHours = 1;
    
    public AuthService(
        IUserRepository userRepository, 
        ITokenService tokenService,
        IPasswordSecurityService passwordSecurityService,
        IJwtBlacklistService jwtBlacklistService,
        ILogger<AuthService> logger,
        IConfiguration configuration)
    {
        _userRepository = userRepository;
        _tokenService = tokenService;
        _passwordSecurityService = passwordSecurityService;
        _jwtBlacklistService = jwtBlacklistService;
        _logger = logger;
        _configuration = configuration;
    }
    
    public async Task<ApiResponseDto<LoginResponseDto>> LoginAsync(LoginRequestDto loginRequest)
    {
        try
        {
            var user = await _userRepository.GetByEmailAsync(loginRequest.Email);
            
            if (user == null)
            {
                _logger.LogWarning("Login attempt for non-existent user: {Email}", loginRequest.Email);
                return ApiResponseDto<LoginResponseDto>.ErrorResponse("Invalid email or password");
            }
            
            // Check if account is locked
            if (await _userRepository.IsAccountLockedAsync(loginRequest.Email))
            {
                _logger.LogWarning("Login attempt for locked account: {Email}", loginRequest.Email);
                return ApiResponseDto<LoginResponseDto>.ErrorResponse("Account is temporarily locked due to too many failed attempts");
            }
            
            // Verify password
            if (!BCrypt.Net.BCrypt.Verify(loginRequest.Password, user.PasswordHash))
            {
                await HandleFailedLoginAttempt(user.Email);
                _logger.LogWarning("Failed login attempt for user: {Email}", loginRequest.Email);
                return ApiResponseDto<LoginResponseDto>.ErrorResponse("Invalid email or password");
            }
            
            // Successful login - reset failed attempts
            await _userRepository.ResetFailedLoginAttemptsAsync(user.Email);
            
            // Update last login
            user.LastLoginAt = DateTime.UtcNow;
            await _userRepository.UpdateAsync(user);
            
            // Generate tokens
            var token = _tokenService.GenerateJwtToken(user.Id, user.Email);
            var refreshToken = _tokenService.GenerateRefreshToken();
            
            // Store refresh token (in a real app, this would be in the database)
            if (_tokenService is TokenService tokenService)
            {
                tokenService.StoreRefreshToken(refreshToken, user.Id);
            }
            
            var response = new LoginResponseDto
            {
                Token = token,
                RefreshToken = refreshToken,
                ExpiresAt = _tokenService.GetTokenExpiry(token),
                User = user
            };
            
            _logger.LogInformation("Successful login for user: {Email}", loginRequest.Email);
            return ApiResponseDto<LoginResponseDto>.SuccessResponse(response, "Login successful");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during login for user: {Email}", loginRequest.Email);
            return ApiResponseDto<LoginResponseDto>.ErrorResponse("An error occurred during login");
        }
    }
    
    public async Task<ApiResponseDto<UserDto>> RegisterAsync(RegisterRequestDto registerRequest)
    {
        try
        {
            // Check if user already exists
            if (await _userRepository.ExistsAsync(registerRequest.Email))
            {
                return ApiResponseDto<UserDto>.ErrorResponse("User with this email already exists");
            }
            
            // Additional password strength validation
            var (isValidPassword, passwordErrors) = await _passwordSecurityService.ValidatePasswordStrengthAsync(
                registerRequest.Password, registerRequest.Email);
            
            if (!isValidPassword)
            {
                return ApiResponseDto<UserDto>.ErrorResponse(
                    "Password does not meet security requirements", 
                    new Dictionary<string, string[]> { { "Password", passwordErrors } });
            }

            // Create user from DTO using implicit operator
            User user = registerRequest;
            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(registerRequest.Password);
            
            // Store password in history
            await _passwordSecurityService.StorePasswordHistoryAsync(user.Id, user.PasswordHash);
            
            // Generate email verification token
            user.EmailVerificationToken = GenerateSecureToken();
            user.EmailVerificationTokenExpiry = DateTime.UtcNow.AddHours(24);
            
            // Save user
            var createdUser = await _userRepository.CreateAsync(user);
            
            _logger.LogInformation("User registered successfully: {Email}", registerRequest.Email);
            
            // In a real application, you would send an email verification here
            // await _emailService.SendVerificationEmailAsync(createdUser.Email, createdUser.EmailVerificationToken);
            
            UserDto userDto = createdUser;
            return ApiResponseDto<UserDto>.SuccessResponse(userDto, "Registration successful. Please check your email to verify your account.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during registration for user: {Email}", registerRequest.Email);
            return ApiResponseDto<UserDto>.ErrorResponse("An error occurred during registration");
        }
    }
    
    public async Task<ApiResponseDto<string>> RequestPasswordResetAsync(PasswordResetRequestDto request)
    {
        try
        {
            var user = await _userRepository.GetByEmailAsync(request.Email);
            
            if (user == null)
            {
                // Don't reveal that the user doesn't exist
                _logger.LogWarning("Password reset requested for non-existent user: {Email}", request.Email);
                return ApiResponseExtensions.SuccessMessage("If an account with that email exists, a password reset link has been sent.");
            }
            
            // Generate reset token
            user.PasswordResetToken = GenerateSecureToken();
            user.PasswordResetTokenExpiry = DateTime.UtcNow.AddHours(1);
            
            await _userRepository.UpdateAsync(user);
            
            _logger.LogInformation("Password reset requested for user: {Email}", request.Email);
            
            // In a real application, you would send an email here
            // await _emailService.SendPasswordResetEmailAsync(user.Email, user.PasswordResetToken);
            
            return ApiResponseExtensions.SuccessMessage("If an account with that email exists, a password reset link has been sent.");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during password reset request for: {Email}", request.Email);
            return ApiResponseDto<string>.ErrorResponse("An error occurred while processing your request");
        }
    }
    
    public async Task<ApiResponseDto<string>> ResetPasswordAsync(PasswordResetDto resetRequest)
    {
        try
        {
            var user = await _userRepository.GetByPasswordResetTokenAsync(resetRequest.Token);
            
            if (user == null)
            {
                return ApiResponseDto<string>.ErrorResponse("Invalid or expired reset token");
            }
            
            // Additional password strength validation
            var (isValidPassword, passwordErrors) = await _passwordSecurityService.ValidatePasswordStrengthAsync(
                resetRequest.NewPassword, user.Email);
            
            if (!isValidPassword)
            {
                return ApiResponseDto<string>.ErrorResponse(
                    string.Join(" ", passwordErrors));
            }

            // Check if password was recently used
            if (await _passwordSecurityService.IsPasswordRecentlyUsedAsync(user.Id, resetRequest.NewPassword))
            {
                return ApiResponseDto<string>.ErrorResponse("Cannot reuse a recently used password. Please choose a different password.");
            }

            // Update password
            var newPasswordHash = BCrypt.Net.BCrypt.HashPassword(resetRequest.NewPassword);
            user.PasswordHash = newPasswordHash;
            user.PasswordResetToken = null;
            user.PasswordResetTokenExpiry = null;
            
            // Store password in history
            await _passwordSecurityService.StorePasswordHistoryAsync(user.Id, newPasswordHash);
            
            // Reset failed login attempts
            user.FailedLoginAttempts = 0;
            user.IsAccountLocked = false;
            user.LockedUntil = null;
            
            await _userRepository.UpdateAsync(user);
            
            _logger.LogInformation("Password reset successfully for user: {Email}", user.Email);
            return ApiResponseExtensions.SuccessMessage("Password has been reset successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during password reset");
            return ApiResponseDto<string>.ErrorResponse("An error occurred while resetting your password");
        }
    }
    
    public async Task<ApiResponseDto<string>> ChangePasswordAsync(Guid userId, ChangePasswordDto changePasswordRequest)
    {
        try
        {
            var user = await _userRepository.GetByIdAsync(userId);
            
            if (user == null)
            {
                return ApiResponseDto<string>.ErrorResponse("User not found");
            }
            
            // Verify current password
            if (!BCrypt.Net.BCrypt.Verify(changePasswordRequest.CurrentPassword, user.PasswordHash))
            {
                return ApiResponseDto<string>.ErrorResponse("Current password is incorrect");
            }

            // Additional password strength validation
            var (isValidPassword, passwordErrors) = await _passwordSecurityService.ValidatePasswordStrengthAsync(
                changePasswordRequest.NewPassword, user.Email);
            
            if (!isValidPassword)
            {
                return ApiResponseDto<string>.ErrorResponse(
                    string.Join(" ", passwordErrors));
            }

            // Check if password was recently used
            if (await _passwordSecurityService.IsPasswordRecentlyUsedAsync(userId, changePasswordRequest.NewPassword))
            {
                return ApiResponseDto<string>.ErrorResponse("Cannot reuse a recently used password. Please choose a different password.");
            }
            
            // Update password
            var newPasswordHash = BCrypt.Net.BCrypt.HashPassword(changePasswordRequest.NewPassword);
            user.PasswordHash = newPasswordHash;
            
            // Store password in history
            await _passwordSecurityService.StorePasswordHistoryAsync(userId, newPasswordHash);
            
            await _userRepository.UpdateAsync(user);
            
            _logger.LogInformation("Password changed successfully for user: {Email}", user.Email);
            return ApiResponseExtensions.SuccessMessage("Password has been changed successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during password change for user: {UserId}", userId);
            return ApiResponseDto<string>.ErrorResponse("An error occurred while changing your password");
        }
    }
    
    public async Task<ApiResponseDto<string>> VerifyEmailAsync(string token)
    {
        try
        {
            var user = await _userRepository.GetByEmailVerificationTokenAsync(token);
            
            if (user == null)
            {
                return ApiResponseDto<string>.ErrorResponse("Invalid or expired verification token");
            }
            
            user.IsEmailVerified = true;
            user.EmailVerificationToken = null;
            user.EmailVerificationTokenExpiry = null;
            
            await _userRepository.UpdateAsync(user);
            
            _logger.LogInformation("Email verified successfully for user: {Email}", user.Email);
            return ApiResponseExtensions.SuccessMessage("Email has been verified successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during email verification");
            return ApiResponseDto<string>.ErrorResponse("An error occurred while verifying your email");
        }
    }
    
    public async Task<ApiResponseDto<LoginResponseDto>> RefreshTokenAsync(string refreshToken)
    {
        try
        {
            if (!await _tokenService.ValidateRefreshTokenAsync(refreshToken))
            {
                return ApiResponseDto<LoginResponseDto>.ErrorResponse("Invalid refresh token");
            }
            
            Guid? userId = null;
            if (_tokenService is TokenService tokenService)
            {
                userId = tokenService.GetUserIdFromRefreshToken(refreshToken);
            }
            
            if (userId == null)
            {
                return ApiResponseDto<LoginResponseDto>.ErrorResponse("Invalid refresh token");
            }
            
            var user = await _userRepository.GetByIdAsync(userId.Value);
            
            if (user == null)
            {
                return ApiResponseDto<LoginResponseDto>.ErrorResponse("User not found");
            }
            
            // Generate new tokens
            var newToken = _tokenService.GenerateJwtToken(user.Id, user.Email);
            var newRefreshToken = _tokenService.GenerateRefreshToken();
            
            // Revoke old refresh token and store new one
            await _tokenService.RevokeRefreshTokenAsync(refreshToken);
            
            if (_tokenService is TokenService ts)
            {
                ts.StoreRefreshToken(newRefreshToken, user.Id);
            }
            
            var response = new LoginResponseDto
            {
                Token = newToken,
                RefreshToken = newRefreshToken,
                ExpiresAt = _tokenService.GetTokenExpiry(newToken),
                User = user
            };
            
            return ApiResponseDto<LoginResponseDto>.SuccessResponse(response, "Token refreshed successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during token refresh");
            return ApiResponseDto<LoginResponseDto>.ErrorResponse("An error occurred while refreshing your token");
        }
    }
    
    public async Task<ApiResponseDto<string>> LogoutAsync(string token)
    {
        try
        {
            // Blacklist the JWT token to prevent reuse
            await _jwtBlacklistService.BlacklistTokenAsync(token);
            
            _logger.LogInformation("User logged out successfully and token blacklisted");
            return ApiResponseExtensions.SuccessMessage("Logged out successfully");
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error during logout");
            return ApiResponseDto<string>.ErrorResponse("An error occurred during logout");
        }
    }
    
    public async Task UnlockExpiredAccountsAsync()
    {
        try
        {
            var lockedUsers = await _userRepository.GetLockedUsersAsync();
            
            foreach (var user in lockedUsers)
            {
                user.IsAccountLocked = false;
                user.LockedUntil = null;
                user.FailedLoginAttempts = 0;
                await _userRepository.UpdateAsync(user);
                _logger.LogInformation("Unlocked expired account for user: {Email}", user.Email);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error unlocking expired accounts");
        }
    }
    
    private async Task HandleFailedLoginAttempt(string email)
    {
        await _userRepository.IncrementFailedLoginAttemptsAsync(email);
        
        var failedAttempts = await _userRepository.GetFailedLoginAttemptsAsync(email);
        
        if (failedAttempts >= MaxFailedAttempts)
        {
            var lockUntil = DateTime.UtcNow.AddHours(LockoutDurationHours);
            await _userRepository.LockAccountAsync(email, lockUntil);
            _logger.LogWarning("Account locked for user: {Email} due to {FailedAttempts} failed attempts", email, failedAttempts);
        }
    }
    
    private static string GenerateSecureToken()
    {
        using var rng = RandomNumberGenerator.Create();
        var bytes = new byte[32];
        rng.GetBytes(bytes);
        return Convert.ToBase64String(bytes).Replace("+", "-").Replace("/", "_").Replace("=", "");
    }
}