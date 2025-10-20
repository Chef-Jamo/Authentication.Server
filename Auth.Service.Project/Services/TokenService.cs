using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Service.Project.Services;

public class TokenService : ITokenService
{
    private readonly IConfiguration _configuration;
    private readonly HashSet<string> _revokedTokens = new();
    private readonly Dictionary<string, Guid> _refreshTokens = new();
    
    public TokenService(IConfiguration configuration)
    {
        _configuration = configuration;
    }
    
    public string GenerateJwtToken(Guid userId, string email)
    {
        var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Secret"] ?? throw new InvalidOperationException("JWT Secret not configured"));
        var tokenHandler = new JwtSecurityTokenHandler();
        
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.NameIdentifier, userId.ToString()),
                new Claim(ClaimTypes.Email, email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            }),
            Expires = DateTime.UtcNow.AddHours(1),
            Issuer = _configuration["Jwt:Issuer"],
            Audience = _configuration["Jwt:Audience"],
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }
    
    public string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
    
    public Task<bool> ValidateRefreshTokenAsync(string refreshToken)
    {
        return Task.FromResult(_refreshTokens.ContainsKey(refreshToken) && !_revokedTokens.Contains(refreshToken));
    }
    
    public Task RevokeRefreshTokenAsync(string refreshToken)
    {
        _revokedTokens.Add(refreshToken);
        _refreshTokens.Remove(refreshToken);
        return Task.CompletedTask;
    }
    
    public Task<Guid?> GetUserIdFromTokenAsync(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            
            // First try to read the token without validation (for well-formed tokens)
            if (!tokenHandler.CanReadToken(token))
            {
                return Task.FromResult<Guid?>(null);
            }
            
            var jwtToken = tokenHandler.ReadJwtToken(token);
            
            // Try different claim type variations that might be used
            var userIdClaim = jwtToken.Claims.FirstOrDefault(x => 
                x.Type == ClaimTypes.NameIdentifier || 
                x.Type == "sub" || 
                x.Type == JwtRegisteredClaimNames.Sub ||
                x.Type == "nameid");
            
            if (userIdClaim != null && Guid.TryParse(userIdClaim.Value, out var userId))
            {
                return Task.FromResult<Guid?>(userId);
            }
        }
        catch
        {
            // Token parsing failed
        }
        
        return Task.FromResult<Guid?>(null);
    }
    
    public DateTime GetTokenExpiry(string token)
    {
        try
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var jwtToken = tokenHandler.ReadJwtToken(token);
            return jwtToken.ValidTo;
        }
        catch
        {
            return DateTime.MinValue;
        }
    }
    
    public void StoreRefreshToken(string refreshToken, Guid userId)
    {
        _refreshTokens[refreshToken] = userId;
    }
    
    public Guid? GetUserIdFromRefreshToken(string refreshToken)
    {
        return _refreshTokens.TryGetValue(refreshToken, out var userId) ? userId : null;
    }
}