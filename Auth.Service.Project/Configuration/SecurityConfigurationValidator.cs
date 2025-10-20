using Auth.Service.Project.Services;

namespace Auth.Service.Project.Configuration;

/// <summary>
/// Service to validate security configuration on startup
/// </summary>
public interface ISecurityConfigurationValidator
{
    /// <summary>
    /// Validates all security-related configuration settings
    /// </summary>
    Task<(bool IsValid, List<string> Issues)> ValidateAsync();
}

public class SecurityConfigurationValidator : ISecurityConfigurationValidator
{
    private readonly IConfiguration _configuration;
    private readonly IWebHostEnvironment _environment;
    private readonly ISecurityAuditService _auditService;
    private readonly ILogger<SecurityConfigurationValidator> _logger;

    public SecurityConfigurationValidator(
        IConfiguration configuration,
        IWebHostEnvironment environment,
        ISecurityAuditService auditService,
        ILogger<SecurityConfigurationValidator> logger)
    {
        _configuration = configuration;
        _environment = environment;
        _auditService = auditService;
        _logger = logger;
    }

    public async Task<(bool IsValid, List<string> Issues)> ValidateAsync()
    {
        var issues = new List<string>();

        // Validate JWT configuration
        await ValidateJwtConfigurationAsync(issues);

        // Validate database configuration
        await ValidateDatabaseConfigurationAsync(issues);

        // Validate CORS configuration
        await ValidateCorsConfigurationAsync(issues);

        // Validate HTTPS configuration
        await ValidateHttpsConfigurationAsync(issues);

        // Validate logging configuration
        await ValidateLoggingConfigurationAsync(issues);

        // Environment-specific validations
        if (_environment.IsProduction())
        {
            await ValidateProductionConfigurationAsync(issues);
        }

        var isValid = issues.Count == 0;

        if (!isValid)
        {
            foreach (var issue in issues)
            {
                await _auditService.LogSecurityConfigurationIssueAsync(issue, "High");
            }
        }

        return (isValid, issues);
    }

    private async Task ValidateJwtConfigurationAsync(List<string> issues)
    {
        var jwtSecret = _configuration["Jwt:Secret"];
        
        if (string.IsNullOrEmpty(jwtSecret))
        {
            issues.Add("JWT Secret is not configured");
        }
        else if (jwtSecret.Length < 32)
        {
            issues.Add("JWT Secret is too short (minimum 32 characters required)");
        }
        else if (jwtSecret == "ThisIsAVeryLongSecretKeyForJWTTokenGenerationThatMustBeAtLeast32Characters")
        {
            issues.Add("JWT Secret is using default/example value - change immediately!");
        }

        var issuer = _configuration["Jwt:Issuer"];
        if (string.IsNullOrEmpty(issuer))
        {
            issues.Add("JWT Issuer is not configured");
        }

        var audience = _configuration["Jwt:Audience"];
        if (string.IsNullOrEmpty(audience))
        {
            issues.Add("JWT Audience is not configured");
        }

        await Task.CompletedTask;
    }

    private async Task ValidateDatabaseConfigurationAsync(List<string> issues)
    {
        var useInMemoryDb = _configuration.GetValue<bool>("UseInMemoryDatabase");
        
        if (useInMemoryDb && _environment.IsProduction())
        {
            issues.Add("In-memory database should not be used in production");
        }

        if (!useInMemoryDb)
        {
            var connectionString = _configuration.GetConnectionString("DefaultConnection");
            if (string.IsNullOrEmpty(connectionString))
            {
                issues.Add("Database connection string is not configured");
            }
            else if (connectionString.Contains("password", StringComparison.OrdinalIgnoreCase) && 
                     connectionString.Contains("Password=password", StringComparison.OrdinalIgnoreCase))
            {
                issues.Add("Database connection string contains default password");
            }
        }

        await Task.CompletedTask;
    }

    private async Task ValidateCorsConfigurationAsync(List<string> issues)
    {
        // This would need to be enhanced based on actual CORS policy registration
        // For now, just warn about development CORS in production
        if (_environment.IsProduction())
        {
            // Check if any CORS policy allows all origins
            issues.Add("Review CORS policy - ensure it's restricted to specific origins in production");
        }

        await Task.CompletedTask;
    }

    private async Task ValidateHttpsConfigurationAsync(List<string> issues)
    {
        if (_environment.IsProduction())
        {
            // Check if HTTPS redirection is enabled
            // This is a basic check - in real scenarios you'd check the actual configuration
            var httpsPort = _configuration["ASPNETCORE_HTTPS_PORT"];
            if (string.IsNullOrEmpty(httpsPort))
            {
                issues.Add("HTTPS port not configured for production");
            }
        }

        await Task.CompletedTask;
    }

    private async Task ValidateLoggingConfigurationAsync(List<string> issues)
    {
        var loggingSection = _configuration.GetSection("Logging");
        if (!loggingSection.Exists())
        {
            issues.Add("Logging configuration is missing");
        }

        // Check if default log level is appropriate
        var defaultLogLevel = loggingSection["LogLevel:Default"];
        if (_environment.IsProduction() && defaultLogLevel == "Debug")
        {
            issues.Add("Debug logging should not be enabled in production");
        }

        await Task.CompletedTask;
    }

    private async Task ValidateProductionConfigurationAsync(List<string> issues)
    {
        // Check for development-only configurations in production
        if (_configuration.GetValue<bool>("Swagger:Enabled", false))
        {
            issues.Add("Swagger/OpenAPI should be disabled in production");
        }

        // Check if detailed errors are disabled
        var detailedErrors = _configuration.GetValue<bool>("DetailedErrors", false);
        if (detailedErrors)
        {
            issues.Add("Detailed errors should be disabled in production");
        }

        // Check for secure headers configuration
        // This would be more sophisticated in a real implementation
        issues.Add("Ensure security headers are properly configured for production");

        await Task.CompletedTask;
    }
}

/// <summary>
/// Hosted service to validate security configuration on startup
/// </summary>
public class SecurityConfigurationValidationService : IHostedService
{
    private readonly IServiceProvider _services;
    private readonly ILogger<SecurityConfigurationValidationService> _logger;

    public SecurityConfigurationValidationService(IServiceProvider services, ILogger<SecurityConfigurationValidationService> logger)
    {
        _services = services;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogInformation("Starting security configuration validation...");

        // Create a scope to resolve scoped services safely
        using var scope = _services.CreateScope();
        var validator = scope.ServiceProvider.GetRequiredService<ISecurityConfigurationValidator>();

        var (isValid, issues) = await validator.ValidateAsync();

        if (!isValid)
        {
            _logger.LogError("Security configuration validation failed with {IssueCount} issues:", issues.Count);

            foreach (var issue in issues)
            {
                _logger.LogError("Security Issue: {Issue}", issue);
            }

            // In a production system, you might want to prevent startup on critical issues
            // throw new InvalidOperationException("Security configuration validation failed");
        }
        else
        {
            _logger.LogInformation("Security configuration validation passed");
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        return Task.CompletedTask;
    }
}