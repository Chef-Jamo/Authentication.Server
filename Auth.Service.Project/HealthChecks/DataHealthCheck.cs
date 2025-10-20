using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Auth.Service.Project.Data;
using Microsoft.EntityFrameworkCore;

namespace Auth.Service.Project.HealthChecks
{
    public class DataHealthCheck : IHealthCheck
    {
        private readonly AuthDbContext _dbContext;

        public DataHealthCheck(AuthDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            try
            {
                // Simple EF Core query to ensure DB is responsive
                await _dbContext.Database.CanConnectAsync(cancellationToken);
                return HealthCheckResult.Healthy("Database connection OK");
            }
            catch (System.Exception ex)
            {
                return HealthCheckResult.Unhealthy("Database connection failed", ex);
            }
        }
    }
}
