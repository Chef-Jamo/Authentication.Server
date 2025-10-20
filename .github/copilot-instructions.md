# Copilot Instructions for Auth.Service.Project

## Project Overview

This is a .NET 9.0 ASP.NET Core Web API project implementing a complete authentication service with JWT tokens, user management, password reset, and account lockout functionality.

## Architecture & Structure

- **Solution Structure**: Uses `.slnx` format with main project and test project
- **Project Path**: `Auth.Service.Project/Auth.Service.Project.csproj`
- **Test Project**: `Auth.Service.Project.Tests/Auth.Service.Project.Tests.csproj`
- **Target Framework**: .NET 9.0 with nullable reference types enabled
- **Architecture Pattern**: Service and Repository layers with dependency injection

## Key Architecture Components

### Layer Structure

- **Controllers**: `Auth.Service.Project.Controllers` - API endpoints
- **Services**: `Auth.Service.Project.Services` - Business logic (AuthService, TokenService)
- **Repositories**: `Auth.Service.Project.Repositories` - Data access (UserRepository)
- **Models**: `Auth.Service.Project.Models` - Entity models (User)
- **DTOs**: `Auth.Service.Project.DTOs` - Data transfer objects with implicit operators
- **Data**: `Auth.Service.Project.Data` - Entity Framework DbContext

### Key Features Implemented

- **User Registration/Login**: Email-based authentication with BCrypt password hashing
- **JWT Authentication**: Token-based auth with refresh tokens
- **Account Lockout**: Auto-lockout after 5 failed attempts (1-hour duration)
- **Password Reset**: Secure token-based password reset flow
- **Email Verification**: Token-based email verification (tokens ready for email service)
- **Background Services**: Automatic unlocking of expired locked accounts

## Authentication Flow

### Core Endpoints

- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login with email/password
- `POST /api/auth/forgot-password` - Request password reset
- `POST /api/auth/reset-password` - Reset password with token
- `POST /api/auth/change-password` - Change password (authenticated)
- `POST /api/auth/verify-email` - Verify email with token
- `POST /api/auth/refresh` - Refresh JWT token
- `POST /api/auth/logout` - Logout user
- `GET /api/auth/profile` - Get user profile (authenticated)

### Security Features

- **Enhanced Password Security**: 12+ char minimum with complexity rules, history tracking, common password detection
- **Rate Limiting**: Comprehensive API rate limiting to prevent brute force attacks
- **Account Lockout**: 5 failed attempts = 1-hour lockout with IP tracking
- **JWT Security**: Token blacklisting, enhanced validation, zero clock skew
- **Input Protection**: XSS prevention, SQL injection detection, request sanitization
- **Security Headers**: HSTS, CSP, X-Frame-Options, and comprehensive header security
- **Data Protection**: Sensitive data encryption at rest using Data Protection API
- **Audit Logging**: Comprehensive security event logging and monitoring
- **Configuration Validation**: Startup security checks and environment-aware hardening
- **Case-Insensitive Email**: All emails stored in lowercase

## Configuration

### Database Options

```json
{
  "UseInMemoryDatabase": true, // Set to false for PostgreSQL
  "ConnectionStrings": {
    "DefaultConnection": "Host=localhost;Database=authservice;Username=postgres;Password=password"
  }
}
```

### JWT Configuration

```json
{
  "Jwt": {
    "Secret": "32+ character secret key",
    "Issuer": "Auth.Service.Project",
    "Audience": "Auth.Service.Project.Client"
  }
}
```

## Development Workflow

### Running the Application

```bash
# Run main project
dotnet run --project Auth.Service.Project/Auth.Service.Project.csproj

# Run tests
dotnet test Auth.Service.Project.Tests/

# Run with test coverage
dotnet test --collect:"XPlat Code Coverage"
```

### Testing Endpoints

- Use `Auth.Service.Project.http` file with comprehensive auth endpoint examples
- Base URL: `http://localhost:5032`
- OpenAPI/Swagger: Available at `/openapi/v1.json` in development

### Key Dependencies

- **Entity Framework**: `Microsoft.EntityFrameworkCore` with PostgreSQL and InMemory providers
- **Authentication**: `Microsoft.AspNetCore.Authentication.JwtBearer`
- **Password Hashing**: `BCrypt.Net-Next`
- **JWT Tokens**: `System.IdentityModel.Tokens.Jwt`
- **Testing**: `xunit`, `Moq`, `FluentAssertions`, `Microsoft.AspNetCore.Mvc.Testing`

## Code Patterns

### DTO Implicit Operators

```csharp
public static implicit operator User(RegisterRequestDto dto)
{
    return new User { Email = dto.Email.ToLowerInvariant(), ... };
}
```

### Repository Pattern

```csharp
public interface IUserRepository
{
    Task<User?> GetByEmailAsync(string email);
    Task<User> CreateAsync(User user);
    // ... other methods
}
```

### Service Layer Pattern

```csharp
public interface IAuthService
{
    Task<ApiResponseDto<LoginResponseDto>> LoginAsync(LoginRequestDto request);
    // ... other methods
}
```

### Response Wrapper

All API responses use `ApiResponseDto<T>` for consistent error handling and success responses.

## Testing Strategy

- **Full Coverage**: Repository, Service, and Controller layers
- **Edge Cases**: Invalid inputs, expired tokens, account lockouts, etc.
- **Integration Ready**: Uses in-memory database for integration tests
- **Mocking**: Services mocked in controller tests, repositories mocked in service tests

## Important Notes

- **Email Service**: Token generation implemented, but email sending needs external service integration
- **Security**: Uses secure random token generation for reset/verification tokens
- **Scalability**: Refresh tokens stored in-memory (consider database storage for production)
- **Logging**: Comprehensive logging for security events (logins, lockouts, etc.)
- **CORS**: Configured to allow all origins (adjust for production)

## Background Services

- `AccountUnlockService`: Runs every 30 minutes to unlock accounts with expired lockout periods
