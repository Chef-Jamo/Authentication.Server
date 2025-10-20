using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace Auth.Service.Project.HealthChecks
{
    public class ExternalEndpointHealthCheck : IHealthCheck
    {
        private readonly HttpClient _httpClient;
        private readonly string _url;

        public ExternalEndpointHealthCheck(HttpClient httpClient, string url)
        {
            _httpClient = httpClient;
            _url = url;
        }

        public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken cancellationToken = default)
        {
            try
            {
                var res = await _httpClient.GetAsync(_url, cancellationToken);
                if (res.IsSuccessStatusCode)
                    return HealthCheckResult.Healthy("External endpoint reachable");

                return HealthCheckResult.Degraded("External endpoint returned non-success status");
            }
            catch (System.Exception ex)
            {
                return HealthCheckResult.Unhealthy("External endpoint unreachable", ex);
            }
        }
    }
}
