using Auth.Service.Project.DTOs;

namespace Auth.Service.Project.Services;

public interface IAuthService
{
    Task<ApiResponseDto<LoginResponseDto>> LoginAsync(LoginRequestDto loginRequest);
    Task<ApiResponseDto<UserDto>> RegisterAsync(RegisterRequestDto registerRequest);
    Task<ApiResponseDto<string>> RequestPasswordResetAsync(PasswordResetRequestDto request);
    Task<ApiResponseDto<string>> ResetPasswordAsync(PasswordResetDto resetRequest);
    Task<ApiResponseDto<string>> ChangePasswordAsync(Guid userId, ChangePasswordDto changePasswordRequest);
    Task<ApiResponseDto<string>> VerifyEmailAsync(string token);
    Task<ApiResponseDto<LoginResponseDto>> RefreshTokenAsync(string refreshToken);
    Task<ApiResponseDto<string>> LogoutAsync(string token);
    Task UnlockExpiredAccountsAsync();
}