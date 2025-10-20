using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using System.Text;
using System.Collections.Concurrent;

namespace Auth.Service.Project.Middleware
{
    public class MetricsMiddleware
    {
        private readonly RequestDelegate _next;
        private static readonly ConcurrentDictionary<string, long> Counters = new();

        public MetricsMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            Counters.AddOrUpdate("requests_total", 1, (_, v) => v + 1);

            if (context.Request.Path == "/metrics")
            {
                context.Response.ContentType = "text/plain; version=0.0.4";
                var sb = new StringBuilder();
                foreach (var kv in Counters)
                {
                    sb.AppendLine($"{kv.Key} {kv.Value}");
                }
                await context.Response.WriteAsync(sb.ToString());
                return;
            }

            await _next(context);
        }
    }
}
