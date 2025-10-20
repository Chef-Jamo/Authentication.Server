using System.ComponentModel.DataAnnotations;
using Auth.Service.Project.Models;
using Auth.Service.Project.Validators;

namespace Auth.Service.Project.DTOs;

public record RegisterRequestDto
{
    [Required]
    [EmailAddress]
    public string Email { get; init; } = string.Empty;
    
    [Required]
    [StrongPassword]
    public string Password { get; init; } = string.Empty;
    
    [Required]
    [MinLength(2)]
    public string FirstName { get; init; } = string.Empty;
    
    [Required]
    [MinLength(2)]
    public string LastName { get; init; } = string.Empty;
    
    public static implicit operator User(RegisterRequestDto dto)
    {
        return new User
        {
            Email = dto.Email.ToLowerInvariant(),
            FirstName = dto.FirstName,
            LastName = dto.LastName
        };
    }
}

public record LoginRequestDto
{
    [Required]
    [EmailAddress]
    public string Email { get; init; } = string.Empty;
    
    [Required]
    public string Password { get; init; } = string.Empty;
}

public record LoginResponseDto
{
    public string Token { get; init; } = string.Empty;
    public string RefreshToken { get; init; } = string.Empty;
    public DateTime ExpiresAt { get; init; }
    public UserDto User { get; init; } = new();
    
    public static implicit operator LoginResponseDto((string token, string refreshToken, DateTime expiresAt, User user) data)
    {
        return new LoginResponseDto
        {
            Token = data.token,
            RefreshToken = data.refreshToken,
            ExpiresAt = data.expiresAt,
            User = data.user
        };
    }
}

public record UserDto
{
    public Guid Id { get; init; }
    public string Email { get; init; } = string.Empty;
    public string FirstName { get; init; } = string.Empty;
    public string LastName { get; init; } = string.Empty;
    public string FullName { get; init; } = string.Empty;
    public bool IsEmailVerified { get; init; }
    public DateTime? LastLoginAt { get; init; }
    public DateTime CreatedAt { get; init; }
    
    public static implicit operator UserDto(User user)
    {
        return new UserDto
        {
            Id = user.Id,
            Email = user.Email,
            FirstName = user.FirstName,
            LastName = user.LastName,
            FullName = user.FullName,
            IsEmailVerified = user.IsEmailVerified,
            LastLoginAt = user.LastLoginAt,
            CreatedAt = user.CreatedAt
        };
    }
}

public record PasswordResetRequestDto
{
    [Required]
    [EmailAddress]
    public string Email { get; init; } = string.Empty;
}

public record PasswordResetDto
{
    [Required]
    public string Token { get; init; } = string.Empty;
    
    [Required]
    [StrongPassword]
    public string NewPassword { get; init; } = string.Empty;
}

public record ChangePasswordDto
{
    [Required]
    public string CurrentPassword { get; init; } = string.Empty;
    
    [Required]
    [StrongPassword]
    public string NewPassword { get; init; } = string.Empty;
}

public record ApiResponseDto<T>
{
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
    public T? Data { get; init; }
    public Dictionary<string, string[]>? Errors { get; init; }
    
    public static ApiResponseDto<T> SuccessResponse(T data, string message = "Success")
    {
        return new ApiResponseDto<T>
        {
            Success = true,
            Message = message,
            Data = data
        };
    }
    
    public static ApiResponseDto<T> ErrorResponse(string message, Dictionary<string, string[]>? errors = null)
    {
        return new ApiResponseDto<T>
        {
            Success = false,
            Message = message,
            Errors = errors
        };
    }
}

// Extension for string-specific success responses to avoid parameter confusion
public static class ApiResponseExtensions 
{
    public static ApiResponseDto<string> SuccessMessage(string message)
    {
        return new ApiResponseDto<string>
        {
            Success = true,
            Message = message,
            Data = message
        };
    }
}