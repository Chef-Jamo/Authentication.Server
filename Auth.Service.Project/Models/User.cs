using System.ComponentModel.DataAnnotations;

namespace Auth.Service.Project.Models;

public class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
    
    [Required]
    public string PasswordHash { get; set; } = string.Empty;
    
    [Required]
    public string FirstName { get; set; } = string.Empty;
    
    [Required]
    public string LastName { get; set; } = string.Empty;
    
    public bool IsEmailVerified { get; set; } = false;
    
    public bool IsAccountLocked { get; set; } = false;
    
    public int FailedLoginAttempts { get; set; } = 0;
    
    public DateTime? LockedUntil { get; set; }
    
    public DateTime? LastLoginAt { get; set; }
    
    public string? LastLoginIpAddress { get; set; }
    
    public DateTime? LastPasswordChangeAt { get; set; }
    
    public string? PasswordResetToken { get; set; }
    
    public DateTime? PasswordResetTokenExpiry { get; set; }
    
    public string? EmailVerificationToken { get; set; }
    
    public DateTime? EmailVerificationTokenExpiry { get; set; }
    
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    
    public DateTime UpdatedAt { get; set; } = DateTime.UtcNow;
    
    // Security tracking
    public int TotalLoginAttempts { get; set; } = 0;
    
    public DateTime? LastFailedLoginAt { get; set; }
    
    public string? LastFailedLoginIpAddress { get; set; }
    
    public string FullName => $"{FirstName} {LastName}";
    
    public bool IsAccountLockedAndNotExpired => IsAccountLocked && LockedUntil.HasValue && LockedUntil > DateTime.UtcNow;
}