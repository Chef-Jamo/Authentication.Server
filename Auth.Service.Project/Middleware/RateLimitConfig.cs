using AspNetCoreRateLimit;

namespace Auth.Service.Project.Middleware;

/// <summary>
/// Configuration for rate limiting specific to authentication endpoints
/// </summary>
public static class RateLimitConfig
{
    /// <summary>
    /// Configure IP-based rate limiting for authentication endpoints
    /// </summary>
    /// <param name="services"></param>
    /// <param name="configuration"></param>
    public static void ConfigureRateLimit(this IServiceCollection services, IConfiguration configuration)
    {
        // Add memory cache for rate limiting
        services.AddMemoryCache();

        // Configure IP rate limiting
        services.Configure<IpRateLimitOptions>(options =>
        {
            // Global rate limits
            options.EnableEndpointRateLimiting = true;
            options.StackBlockedRequests = false;
            options.HttpStatusCode = 429;
            options.RealIpHeader = "X-Real-IP";
            options.ClientIdHeader = "X-ClientId";
            options.GeneralRules = new List<RateLimitRule>
            {
                // General API limit - 100 requests per minute per IP
                new RateLimitRule
                {
                    Endpoint = "*",
                    Period = "1m",
                    Limit = 100,
                },
                // Login endpoint - 5 attempts per minute per IP
                new RateLimitRule
                {
                    Endpoint = "POST:/api/auth/login",
                    Period = "1m",
                    Limit = 5,
                },
                // Registration - 3 attempts per minute per IP
                new RateLimitRule
                {
                    Endpoint = "POST:/api/auth/register", 
                    Period = "1m",
                    Limit = 3,
                },
                // Password reset request - 3 attempts per hour per IP
                new RateLimitRule
                {
                    Endpoint = "POST:/api/auth/forgot-password",
                    Period = "1h", 
                    Limit = 3,
                },
                // Password reset - 10 attempts per hour per IP
                new RateLimitRule
                {
                    Endpoint = "POST:/api/auth/reset-password",
                    Period = "1h",
                    Limit = 10,
                },
                // Email verification - 10 attempts per hour per IP
                new RateLimitRule
                {
                    Endpoint = "POST:/api/auth/verify-email",
                    Period = "1h", 
                    Limit = 10,
                },
                // Token refresh - 20 requests per minute per IP
                new RateLimitRule
                {
                    Endpoint = "POST:/api/auth/refresh",
                    Period = "1m",
                    Limit = 20,
                }
            };
        });

        // Configure Client rate limiting (optional, for authenticated users)
        services.Configure<ClientRateLimitOptions>(options =>
        {
            options.EnableEndpointRateLimiting = true;
            options.StackBlockedRequests = false;
            options.HttpStatusCode = 429;
            options.GeneralRules = new List<RateLimitRule>
            {
                // Authenticated users get higher limits
                new RateLimitRule
                {
                    Endpoint = "*",
                    Period = "1m", 
                    Limit = 200,
                }
            };
        });

        // Add IP rate limiting policy store and counter store
        services.AddSingleton<IIpPolicyStore, MemoryCacheIpPolicyStore>();
        services.AddSingleton<IRateLimitCounterStore, MemoryCacheRateLimitCounterStore>();

        // Add client rate limiting stores (for authenticated users)
        services.AddSingleton<IClientPolicyStore, MemoryCacheClientPolicyStore>(); 
        
        // Add rate limiting services
        services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();
        services.AddSingleton<IProcessingStrategy, AsyncKeyLockProcessingStrategy>();
    }
}