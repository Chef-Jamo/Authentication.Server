using AspNetCoreRateLimit;
using Auth.Service.Project.Configuration;
using Auth.Service.Project.Data;
using Auth.Service.Project.HealthChecks;
using Auth.Service.Project.Middleware;
using Auth.Service.Project.Repositories;
using Auth.Service.Project.Services;
using Auth.Service.Project.Validators;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Diagnostics.HealthChecks;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Text;
using System.Text.Json;

WebApplicationBuilder builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllers();

// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
// Register minimal OpenAPI/Swagger and configure JWT security scheme
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo { Title = "Auth.Service.Project API", Version = "v1" });

    // Add JWT Bearer authentication to Swagger
    var jwtSecurityScheme = new OpenApiSecurityScheme
    {
        Scheme = "bearer",
        BearerFormat = "JWT",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Description = "Enter 'Bearer' [space] and then your valid token in the text input below.\n\nExample: \"Bearer eyJhb...\"",
        Reference = new OpenApiReference
        {
            Id = JwtBearerDefaults.AuthenticationScheme,
            Type = ReferenceType.SecurityScheme
        }
    };

    options.AddSecurityDefinition(jwtSecurityScheme.Reference.Id, jwtSecurityScheme);
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        { jwtSecurityScheme, new string[] { } }
    });
});

// Configure Entity Framework
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
var useInMemoryDb = builder.Configuration.GetValue<bool>("UseInMemoryDatabase");

if (useInMemoryDb || string.IsNullOrEmpty(connectionString))
{
    builder.Services.AddDbContext<AuthDbContext>(options =>
        options.UseInMemoryDatabase("AuthServiceDb"));
}
else
{
    builder.Services.AddDbContext<AuthDbContext>(options =>
        options.UseNpgsql(connectionString));
}

// Configure JWT Authentication with enhanced security
var jwtSecret = builder.Configuration["Jwt:Secret"];
if (string.IsNullOrEmpty(jwtSecret))
{
    throw new InvalidOperationException("JWT Secret must be configured");
}

if (jwtSecret.Length < 32)
{
    throw new InvalidOperationException("JWT Secret must be at least 32 characters long for security");
}

var key = Encoding.UTF8.GetBytes(jwtSecret);

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment(); // Require HTTPS in production
    options.SaveToken = false; // Don't save token in HttpContext for security
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidateAudience = true,
        ValidAudience = builder.Configuration["Jwt:Audience"],
        ValidateLifetime = true,
        ClockSkew = TimeSpan.Zero, // No tolerance for clock skew
        RequireExpirationTime = true,
        RequireSignedTokens = true
    };

    // Enhanced token validation events
    options.Events = new JwtBearerEvents
    {
        OnTokenValidated = context =>
        {
            // Additional token validation can be added here
            return Task.CompletedTask;
        },
        OnAuthenticationFailed = context =>
        {
            // Log authentication failures
            ILogger<Program> logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogWarning("JWT Authentication failed: {Error}", context.Exception.Message);
            return Task.CompletedTask;
        },
        OnChallenge = context =>
        {
            // Custom challenge response
            context.HandleResponse();
            context.Response.StatusCode = 401;
            context.Response.ContentType = "application/json";
            var result = System.Text.Json.JsonSerializer.Serialize(new { error = "Invalid or expired token" });
            return context.Response.WriteAsync(result);
        }
    };
});

builder.Services.AddAuthorization();

// Configure Data Protection
builder.Services.AddDataProtection();

// Configure rate limiting
builder.Services.ConfigureRateLimit(builder.Configuration);

// Register core services
builder.Services.AddScoped<IUserRepository, UserRepository>();
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<ITokenService, TokenService>();

// Register security services
builder.Services.AddScoped<IPasswordSecurityService, PasswordSecurityService>();
builder.Services.AddScoped<IJwtBlacklistService, JwtBlacklistService>();
builder.Services.AddScoped<IDataProtectionService, DataProtectionService>();
builder.Services.AddScoped<ISecurityAuditService, SecurityAuditService>();
builder.Services.AddScoped<ISecurityConfigurationValidator, SecurityConfigurationValidator>();

// Register hosted services
builder.Services.AddHostedService<SecurityConfigurationValidationService>();

// Add CORS - Secure configuration for production
builder.Services.AddCors(options =>
{
    options.AddPolicy("SecureCorsPolicy", policy =>
    {
        if (builder.Environment.IsDevelopment())
        {
            // Development: Allow all origins for testing
            policy.AllowAnyOrigin()
                  .AllowAnyMethod()
                  .AllowAnyHeader();
        }
        else
        {
            // Production: Restrict to specific origins
            policy.WithOrigins("https://yourdomain.com", "https://www.yourdomain.com")
                  .AllowAnyMethod()
                  .AllowAnyHeader()
                  .AllowCredentials();
        }
    });
});

// Add background service for unlocking expired accounts
builder.Services.AddHostedService<AccountUnlockService>();

// Register health checks using a single builder
IHealthChecksBuilder healthBuilder = builder.Services.AddHealthChecks();
healthBuilder.AddCheck<DataHealthCheck>("database");

// Register supporting services and checks
builder.Services.AddHttpClient("ExternalCheck");
// Disk space check: require at least 10MB free on the content root
builder.Services.AddSingleton(new DiskSpaceHealthCheck(builder.Environment.ContentRootPath, 10 * 1024 * 1024));
healthBuilder.AddCheck<DiskSpaceHealthCheck>("disk");

// External endpoint check using a factory so we can pass a named HttpClient and configuration
// Register typed ExternalEndpointHealthCheck so healthBuilder can add it
builder.Services.AddTransient<ExternalEndpointHealthCheck>(sp =>
    new ExternalEndpointHealthCheck(sp.GetRequiredService<IHttpClientFactory>().CreateClient("ExternalCheck"), builder.Configuration["Health:ExternalUrl"] ?? "https://example.com")
);
healthBuilder.AddCheck<ExternalEndpointHealthCheck>("external");

// (Removed HealthChecks UI integration due to storage dependencies; using a lightweight static UI)


// Configure Swagger protection API key (optional): set in appsettings.json as Swagger:ApiKey
// Metrics middleware does not need DI registrations

WebApplication app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Auth.Service.Project API v1");
        c.RoutePrefix = "swagger"; // Serve at /swagger
    });

    // Ensure database is created for in-memory database
    using IServiceScope scope = app.Services.CreateScope();
    AuthDbContext context = scope.ServiceProvider.GetRequiredService<AuthDbContext>();
    context.Database.EnsureCreated();
}
else
{
    // Protect Swagger in non-dev environments
    app.UseMiddleware<SwaggerProtectionMiddleware>();
}


// Security middleware pipeline - ORDER MATTERS!
app.UseHttpsRedirection();

// Metrics middleware (collects simple request counters and exposes /metrics)
app.UseMiddleware<MetricsMiddleware>();

// Rate limiting
app.UseIpRateLimiting();

// Security headers and input sanitization
app.UseMiddleware<SecurityMiddleware>();

// CORS
app.UseCors("SecureCorsPolicy");

// Authentication & Authorization
app.UseAuthentication();
app.UseMiddleware<JwtValidationMiddleware>();
app.UseAuthorization();

app.MapControllers();

// Health check endpoint with JSON output
app.MapHealthChecks("/health", new HealthCheckOptions
{
    ResponseWriter = async (context, report) =>
    {
        context.Response.ContentType = "application/json";
        var result = JsonSerializer.Serialize(new
        {
            status = report.Status.ToString(),
            checks = report.Entries.Select(e => new { name = e.Key, status = e.Value.Status.ToString(), description = e.Value.Description }),
            totalDuration = report.TotalDuration
        });
        await context.Response.WriteAsync(result);
    }
});

// Readiness: ensure database connectivity (used by orchestrators to verify readiness)
app.MapHealthChecks("/health/ready", new Microsoft.AspNetCore.Diagnostics.HealthChecks.HealthCheckOptions
{
    Predicate = (check) => check.Name == "database",
    ResponseWriter = async (context, report) =>
    {
        context.Response.ContentType = "application/json";
        var result = JsonSerializer.Serialize(new
        {
            status = report.Status.ToString(),
            checks = report.Entries.Select(e => new { name = e.Key, status = e.Value.Status.ToString(), description = e.Value.Description }),
            totalDuration = report.TotalDuration
        });
        await context.Response.WriteAsync(result);
    }
});

// Liveness: simple check to confirm the app is running
app.MapGet("/health/live", () => Results.Json(new { status = "Live" }));

// Serve static health UI under /health-ui
app.UseDefaultFiles();
app.UseStaticFiles();
app.MapGet("/health-ui", async context => { context.Response.Redirect("/health-ui/index.html"); await Task.CompletedTask; });

app.Run();
