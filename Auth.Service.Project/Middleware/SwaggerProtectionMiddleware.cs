using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;

namespace Auth.Service.Project.Middleware
{
    public class SwaggerProtectionMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly string? _apiKey;
        private readonly IHostEnvironment _env;

        public SwaggerProtectionMiddleware(RequestDelegate next, IConfiguration config, IHostEnvironment env)
        {
            _next = next;
            _apiKey = config["Swagger:ApiKey"];
            _env = env;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Only protect swagger and health UI endpoints in non-development
            if (!_env.IsDevelopment() && (context.Request.Path.StartsWithSegments("/swagger") || context.Request.Path.StartsWithSegments("/healthchecks-ui")))
            {
                if (string.IsNullOrEmpty(_apiKey))
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    await context.Response.WriteAsync("Swagger is disabled in this environment");
                    return;
                }

                if (!context.Request.Headers.TryGetValue("X-Api-Key", out var provided) || provided != _apiKey)
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    await context.Response.WriteAsync("Missing or invalid X-Api-Key header");
                    return;
                }
            }

            await _next(context);
        }
    }
}
