using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using System.IO;

namespace Auth.Service.Project.HealthChecks
{
    public class DiskSpaceHealthCheck : IHealthCheck
    {
        private readonly string _path;
        private readonly long _minimumFreeBytes;

        public DiskSpaceHealthCheck(string path, long minimumFreeBytes)
        {
            _path = path;
            _minimumFreeBytes = minimumFreeBytes;
        }

        public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            try
            {
                var drive = new DriveInfo(Path.GetPathRoot(_path) ?? _path);
                if (drive.AvailableFreeSpace < _minimumFreeBytes)
                {
                    return Task.FromResult(HealthCheckResult.Unhealthy($"Low disk space on {_path}"));
                }

                return Task.FromResult(HealthCheckResult.Healthy("Sufficient disk space"));
            }
            catch (System.Exception ex)
            {
                return Task.FromResult(HealthCheckResult.Unhealthy("Disk check failed", ex));
            }
        }
    }
}
