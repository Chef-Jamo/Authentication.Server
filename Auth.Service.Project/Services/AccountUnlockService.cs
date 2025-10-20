using Auth.Service.Project.Services;

namespace Auth.Service.Project.Services;

public class AccountUnlockService : BackgroundService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<AccountUnlockService> _logger;
    private readonly TimeSpan _checkInterval = TimeSpan.FromMinutes(30);
    
    public AccountUnlockService(IServiceProvider serviceProvider, ILogger<AccountUnlockService> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }
    
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = _serviceProvider.CreateScope();
                var authService = scope.ServiceProvider.GetRequiredService<IAuthService>();
                
                await authService.UnlockExpiredAccountsAsync();
                _logger.LogInformation("Account unlock check completed at {Time}", DateTime.UtcNow);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during account unlock check");
            }
            
            await Task.Delay(_checkInterval, stoppingToken);
        }
    }
}