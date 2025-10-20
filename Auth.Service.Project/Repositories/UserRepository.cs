using Microsoft.EntityFrameworkCore;
using Auth.Service.Project.Data;
using Auth.Service.Project.Models;

namespace Auth.Service.Project.Repositories;

public class UserRepository : IUserRepository
{
    private readonly AuthDbContext _context;
    
    public UserRepository(AuthDbContext context)
    {
        _context = context;
    }
    
    public async Task<User?> GetByIdAsync(Guid id)
    {
        return await _context.Users.FindAsync(id);
    }
    
    public async Task<User?> GetByEmailAsync(string email)
    {
        return await _context.Users
            .FirstOrDefaultAsync(u => u.Email == email.ToLowerInvariant());
    }
    
    public async Task<User> CreateAsync(User user)
    {
        user.Email = user.Email.ToLowerInvariant();
        _context.Users.Add(user);
        await _context.SaveChangesAsync();
        return user;
    }
    
    public async Task<User> UpdateAsync(User user)
    {
        user.Email = user.Email.ToLowerInvariant();
        _context.Users.Update(user);
        await _context.SaveChangesAsync();
        return user;
    }
    
    public async Task DeleteAsync(Guid id)
    {
        var user = await GetByIdAsync(id);
        if (user != null)
        {
            _context.Users.Remove(user);
            await _context.SaveChangesAsync();
        }
    }
    
    public async Task<bool> ExistsAsync(string email)
    {
        return await _context.Users
            .AnyAsync(u => u.Email == email.ToLowerInvariant());
    }
    
    public async Task<User?> GetByPasswordResetTokenAsync(string token)
    {
        return await _context.Users
            .FirstOrDefaultAsync(u => u.PasswordResetToken == token 
                                   && u.PasswordResetTokenExpiry > DateTime.UtcNow);
    }
    
    public async Task<User?> GetByEmailVerificationTokenAsync(string token)
    {
        return await _context.Users
            .FirstOrDefaultAsync(u => u.EmailVerificationToken == token 
                                   && u.EmailVerificationTokenExpiry > DateTime.UtcNow);
    }
    
    public async Task<IEnumerable<User>> GetLockedUsersAsync()
    {
        return await _context.Users
            .Where(u => u.IsAccountLocked && u.LockedUntil <= DateTime.UtcNow)
            .ToListAsync();
    }
    
    public async Task<int> GetFailedLoginAttemptsAsync(string email)
    {
        var user = await GetByEmailAsync(email);
        return user?.FailedLoginAttempts ?? 0;
    }
    
    public async Task IncrementFailedLoginAttemptsAsync(string email)
    {
        var user = await GetByEmailAsync(email);
        if (user != null)
        {
            user.FailedLoginAttempts++;
            await UpdateAsync(user);
        }
    }
    
    public async Task ResetFailedLoginAttemptsAsync(string email)
    {
        var user = await GetByEmailAsync(email);
        if (user != null)
        {
            user.FailedLoginAttempts = 0;
            user.IsAccountLocked = false;
            user.LockedUntil = null;
            await UpdateAsync(user);
        }
    }
    
    public async Task LockAccountAsync(string email, DateTime lockUntil)
    {
        var user = await GetByEmailAsync(email);
        if (user != null)
        {
            user.IsAccountLocked = true;
            user.LockedUntil = lockUntil;
            await UpdateAsync(user);
        }
    }
    
    public async Task<bool> IsAccountLockedAsync(string email)
    {
        var user = await GetByEmailAsync(email);
        return user?.IsAccountLockedAndNotExpired ?? false;
    }
}