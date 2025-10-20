using FluentAssertions;
using Microsoft.EntityFrameworkCore;
using Auth.Service.Project.Data;
using Auth.Service.Project.Models;
using Auth.Service.Project.Repositories;
using Xunit;

namespace Auth.Service.Project.Tests.Repositories;

public class UserRepositoryTests : IDisposable
{
    private readonly AuthDbContext _context;
    private readonly UserRepository _repository;
    
    public UserRepositoryTests()
    {
        var options = new DbContextOptionsBuilder<AuthDbContext>()
            .UseInMemoryDatabase(databaseName: Guid.NewGuid().ToString())
            .Options;
        
        _context = new AuthDbContext(options);
        _repository = new UserRepository(_context);
    }
    
    [Fact]
    public async Task GetByEmailAsync_ShouldReturnUser_WhenUserExists()
    {
        // Arrange
        var user = new User
        {
            Email = "test@example.com",
            PasswordHash = "hashedpassword",
            FirstName = "Test",
            LastName = "User"
        };
        
        await _context.Users.AddAsync(user);
        await _context.SaveChangesAsync();
        
        // Act
        var result = await _repository.GetByEmailAsync("test@example.com");
        
        // Assert
        result.Should().NotBeNull();
        result!.Email.Should().Be("test@example.com");
    }
    
    [Fact]
    public async Task GetByEmailAsync_ShouldBeCaseInsensitive()
    {
        // Arrange
        var user = new User
        {
            Email = "test@example.com",
            PasswordHash = "hashedpassword",
            FirstName = "Test",
            LastName = "User"
        };
        
        await _context.Users.AddAsync(user);
        await _context.SaveChangesAsync();
        
        // Act
        var result = await _repository.GetByEmailAsync("TEST@EXAMPLE.COM");
        
        // Assert
        result.Should().NotBeNull();
        result!.Email.Should().Be("test@example.com");
    }
    
    [Fact]
    public async Task GetByEmailAsync_ShouldReturnNull_WhenUserDoesNotExist()
    {
        // Act
        var result = await _repository.GetByEmailAsync("nonexistent@example.com");
        
        // Assert
        result.Should().BeNull();
    }
    
    [Fact]
    public async Task CreateAsync_ShouldCreateUser_WithLowercaseEmail()
    {
        // Arrange
        var user = new User
        {
            Email = "TEST@EXAMPLE.COM",
            PasswordHash = "hashedpassword",
            FirstName = "Test",
            LastName = "User"
        };
        
        // Act
        var result = await _repository.CreateAsync(user);
        
        // Assert
        result.Should().NotBeNull();
        result.Email.Should().Be("test@example.com");
        
        var dbUser = await _context.Users.FirstOrDefaultAsync(u => u.Id == result.Id);
        dbUser.Should().NotBeNull();
        dbUser!.Email.Should().Be("test@example.com");
    }
    
    [Fact]
    public async Task ExistsAsync_ShouldReturnTrue_WhenUserExists()
    {
        // Arrange
        var user = new User
        {
            Email = "test@example.com",
            PasswordHash = "hashedpassword",
            FirstName = "Test",
            LastName = "User"
        };
        
        await _context.Users.AddAsync(user);
        await _context.SaveChangesAsync();
        
        // Act
        var result = await _repository.ExistsAsync("test@example.com");
        
        // Assert
        result.Should().BeTrue();
    }
    
    [Fact]
    public async Task ExistsAsync_ShouldReturnFalse_WhenUserDoesNotExist()
    {
        // Act
        var result = await _repository.ExistsAsync("nonexistent@example.com");
        
        // Assert
        result.Should().BeFalse();
    }
    
    [Fact]
    public async Task IncrementFailedLoginAttemptsAsync_ShouldIncrementCount()
    {
        // Arrange
        var user = new User
        {
            Email = "test@example.com",
            PasswordHash = "hashedpassword",
            FirstName = "Test",
            LastName = "User",
            FailedLoginAttempts = 2
        };
        
        await _context.Users.AddAsync(user);
        await _context.SaveChangesAsync();
        
        // Act
        await _repository.IncrementFailedLoginAttemptsAsync("test@example.com");
        
        // Assert
        var updatedUser = await _repository.GetByEmailAsync("test@example.com");
        updatedUser!.FailedLoginAttempts.Should().Be(3);
    }
    
    [Fact]
    public async Task LockAccountAsync_ShouldLockAccount()
    {
        // Arrange
        var user = new User
        {
            Email = "test@example.com",
            PasswordHash = "hashedpassword",
            FirstName = "Test",
            LastName = "User"
        };
        
        await _context.Users.AddAsync(user);
        await _context.SaveChangesAsync();
        
        var lockUntil = DateTime.UtcNow.AddHours(1);
        
        // Act
        await _repository.LockAccountAsync("test@example.com", lockUntil);
        
        // Assert
        var lockedUser = await _repository.GetByEmailAsync("test@example.com");
        lockedUser!.IsAccountLocked.Should().BeTrue();
        lockedUser.LockedUntil.Should().BeCloseTo(lockUntil, TimeSpan.FromSeconds(1));
    }
    
    [Fact]
    public async Task IsAccountLockedAsync_ShouldReturnTrue_WhenAccountIsLockedAndNotExpired()
    {
        // Arrange
        var user = new User
        {
            Email = "test@example.com",
            PasswordHash = "hashedpassword",
            FirstName = "Test",
            LastName = "User",
            IsAccountLocked = true,
            LockedUntil = DateTime.UtcNow.AddHours(1)
        };
        
        await _context.Users.AddAsync(user);
        await _context.SaveChangesAsync();
        
        // Act
        var result = await _repository.IsAccountLockedAsync("test@example.com");
        
        // Assert
        result.Should().BeTrue();
    }
    
    [Fact]
    public async Task IsAccountLockedAsync_ShouldReturnFalse_WhenAccountIsLockedButExpired()
    {
        // Arrange
        var user = new User
        {
            Email = "test@example.com",
            PasswordHash = "hashedpassword",
            FirstName = "Test",
            LastName = "User",
            IsAccountLocked = true,
            LockedUntil = DateTime.UtcNow.AddHours(-1)
        };
        
        await _context.Users.AddAsync(user);
        await _context.SaveChangesAsync();
        
        // Act
        var result = await _repository.IsAccountLockedAsync("test@example.com");
        
        // Assert
        result.Should().BeFalse();
    }
    
    [Fact]
    public async Task ResetFailedLoginAttemptsAsync_ShouldResetCountAndUnlockAccount()
    {
        // Arrange
        var user = new User
        {
            Email = "test@example.com",
            PasswordHash = "hashedpassword",
            FirstName = "Test",
            LastName = "User",
            FailedLoginAttempts = 5,
            IsAccountLocked = true,
            LockedUntil = DateTime.UtcNow.AddHours(1)
        };
        
        await _context.Users.AddAsync(user);
        await _context.SaveChangesAsync();
        
        // Act
        await _repository.ResetFailedLoginAttemptsAsync("test@example.com");
        
        // Assert
        var resetUser = await _repository.GetByEmailAsync("test@example.com");
        resetUser!.FailedLoginAttempts.Should().Be(0);
        resetUser.IsAccountLocked.Should().BeFalse();
        resetUser.LockedUntil.Should().BeNull();
    }
    
    [Fact]
    public async Task GetLockedUsersAsync_ShouldReturnOnlyExpiredLockedUsers()
    {
        // Arrange
        var expiredLockedUser = new User
        {
            Email = "expired@example.com",
            PasswordHash = "hashedpassword",
            FirstName = "Expired",
            LastName = "User",
            IsAccountLocked = true,
            LockedUntil = DateTime.UtcNow.AddHours(-1)
        };
        
        var stillLockedUser = new User
        {
            Email = "locked@example.com",
            PasswordHash = "hashedpassword",
            FirstName = "Locked",
            LastName = "User",
            IsAccountLocked = true,
            LockedUntil = DateTime.UtcNow.AddHours(1)
        };
        
        var unlockedUser = new User
        {
            Email = "unlocked@example.com",
            PasswordHash = "hashedpassword",
            FirstName = "Unlocked",
            LastName = "User",
            IsAccountLocked = false
        };
        
        await _context.Users.AddRangeAsync(expiredLockedUser, stillLockedUser, unlockedUser);
        await _context.SaveChangesAsync();
        
        // Act
        var result = await _repository.GetLockedUsersAsync();
        
        // Assert
        result.Should().HaveCount(1);
        result.First().Email.Should().Be("expired@example.com");
    }
    
    public void Dispose()
    {
        _context.Dispose();
    }
}