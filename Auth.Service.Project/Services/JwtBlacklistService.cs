using Microsoft.Extensions.Caching.Memory;
using System.IdentityModel.Tokens.Jwt;

namespace Auth.Service.Project.Services;

/// <summary>
/// Service for managing JWT token blacklist to support secure logout
/// </summary>
public interface IJwtBlacklistService
{
    /// <summary>
    /// Adds a JWT token to the blacklist
    /// </summary>
    Task BlacklistTokenAsync(string token);

    /// <summary>
    /// Checks if a JWT token is blacklisted
    /// </summary>
    Task<bool> IsTokenBlacklistedAsync(string token);

    /// <summary>
    /// Blacklists all tokens for a specific user (useful for security incidents)
    /// </summary>
    Task BlacklistAllUserTokensAsync(Guid userId);

    /// <summary>
    /// Cleans up expired tokens from blacklist
    /// </summary>
    Task CleanupExpiredTokensAsync();
}

public class JwtBlacklistService : IJwtBlacklistService
{
    private readonly IMemoryCache _cache;
    private readonly ILogger<JwtBlacklistService> _logger;
    private readonly HashSet<Guid> _blacklistedUsers = new();

    public JwtBlacklistService(IMemoryCache cache, ILogger<JwtBlacklistService> logger)
    {
        _cache = cache;
        _logger = logger;
    }

    public async Task BlacklistTokenAsync(string token)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jsonToken = handler.ReadJwtToken(token);
            
            // Get token expiration
            var expirationTime = jsonToken.ValidTo;
            
            // Store in cache until token expires
            var cacheKey = $"blacklist_{jsonToken.RawData.GetHashCode()}";
            _cache.Set(cacheKey, true, expirationTime);
            
            _logger.LogInformation("Token blacklisted successfully. Expires at: {ExpirationTime}", expirationTime);
            
            await Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error blacklisting token");
            throw;
        }
    }

    public async Task<bool> IsTokenBlacklistedAsync(string token)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jsonToken = handler.ReadJwtToken(token);
            
            // Check if user is globally blacklisted
            var userIdClaim = jsonToken.Claims.FirstOrDefault(c => c.Type == "nameid");
            if (userIdClaim != null && Guid.TryParse(userIdClaim.Value, out var userId))
            {
                if (_blacklistedUsers.Contains(userId))
                {
                    return true;
                }
            }
            
            // Check if specific token is blacklisted
            var cacheKey = $"blacklist_{jsonToken.RawData.GetHashCode()}";
            var isBlacklisted = _cache.TryGetValue(cacheKey, out _);
            
            await Task.CompletedTask;
            return isBlacklisted;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error checking token blacklist status");
            // In case of error, assume token is not blacklisted to avoid blocking valid users
            return false;
        }
    }

    public async Task BlacklistAllUserTokensAsync(Guid userId)
    {
        _blacklistedUsers.Add(userId);
        _logger.LogWarning("All tokens blacklisted for user: {UserId}", userId);
        await Task.CompletedTask;
    }

    public async Task CleanupExpiredTokensAsync()
    {
        // Memory cache automatically handles cleanup of expired entries
        _logger.LogDebug("Token blacklist cleanup completed");
        await Task.CompletedTask;
    }
}

/// <summary>
/// Enhanced token service with blacklist support
/// </summary>
public interface IEnhancedTokenService : ITokenService
{
    /// <summary>
    /// Validates JWT token and checks blacklist
    /// </summary>
    Task<bool> ValidateAndCheckBlacklistAsync(string token);

    /// <summary>
    /// Extracts user ID from JWT token
    /// </summary>
    Guid? GetUserIdFromToken(string token);

    /// <summary>
    /// Gets remaining time until token expires
    /// </summary>
    TimeSpan? GetTokenRemainingTime(string token);
}

public class EnhancedTokenService : TokenService, IEnhancedTokenService
{
    private readonly IJwtBlacklistService _blacklistService;
    private readonly ILogger<EnhancedTokenService> _logger;

    public EnhancedTokenService(
        IConfiguration configuration, 
        IJwtBlacklistService blacklistService,
        ILogger<EnhancedTokenService> logger) 
        : base(configuration)
    {
        _blacklistService = blacklistService;
        _logger = logger;
    }

    public async Task<bool> ValidateAndCheckBlacklistAsync(string token)
    {
        try
        {
            // First check if token is blacklisted
            if (await _blacklistService.IsTokenBlacklistedAsync(token))
            {
                _logger.LogWarning("Blacklisted token usage attempt");
                return false;
            }

            // Then validate token normally
            return await ValidateRefreshTokenAsync(token); // This calls the base implementation
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error validating token");
            return false;
        }
    }

    public Guid? GetUserIdFromToken(string token)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jsonToken = handler.ReadJwtToken(token);
            
            var userIdClaim = jsonToken.Claims.FirstOrDefault(c => c.Type == "nameid");
            
            if (userIdClaim != null && Guid.TryParse(userIdClaim.Value, out var userId))
            {
                return userId;
            }

            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error extracting user ID from token");
            return null;
        }
    }

    public TimeSpan? GetTokenRemainingTime(string token)
    {
        try
        {
            var handler = new JwtSecurityTokenHandler();
            var jsonToken = handler.ReadJwtToken(token);
            
            var expirationTime = jsonToken.ValidTo;
            var remainingTime = expirationTime - DateTime.UtcNow;
            
            return remainingTime > TimeSpan.Zero ? remainingTime : TimeSpan.Zero;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error calculating token remaining time");
            return null;
        }
    }
}