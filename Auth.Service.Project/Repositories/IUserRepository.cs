using Auth.Service.Project.Models;

namespace Auth.Service.Project.Repositories;

public interface IUserRepository
{
    Task<User?> GetByIdAsync(Guid id);
    Task<User?> GetByEmailAsync(string email);
    Task<User> CreateAsync(User user);
    Task<User> UpdateAsync(User user);
    Task DeleteAsync(Guid id);
    Task<bool> ExistsAsync(string email);
    Task<User?> GetByPasswordResetTokenAsync(string token);
    Task<User?> GetByEmailVerificationTokenAsync(string token);
    Task<IEnumerable<User>> GetLockedUsersAsync();
    Task<int> GetFailedLoginAttemptsAsync(string email);
    Task IncrementFailedLoginAttemptsAsync(string email);
    Task ResetFailedLoginAttemptsAsync(string email);
    Task LockAccountAsync(string email, DateTime lockUntil);
    Task<bool> IsAccountLockedAsync(string email);
}