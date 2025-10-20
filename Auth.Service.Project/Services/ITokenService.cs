using Auth.Service.Project.DTOs;

namespace Auth.Service.Project.Services;

public interface ITokenService
{
    string GenerateJwtToken(Guid userId, string email);
    string GenerateRefreshToken();
    Task<bool> ValidateRefreshTokenAsync(string refreshToken);
    Task RevokeRefreshTokenAsync(string refreshToken);
    Task<Guid?> GetUserIdFromTokenAsync(string token);
    DateTime GetTokenExpiry(string token);
}