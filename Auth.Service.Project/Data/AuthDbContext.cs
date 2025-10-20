using Microsoft.EntityFrameworkCore;
using Auth.Service.Project.Models;

namespace Auth.Service.Project.Data;

public class AuthDbContext : DbContext
{
    public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
    {
    }
    
    public DbSet<User> Users { get; set; }
    
    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);
        
        modelBuilder.Entity<User>(entity =>
        {
            entity.HasKey(e => e.Id);
            
            entity.HasIndex(e => e.Email)
                  .IsUnique();
            
            entity.Property(e => e.Email)
                  .IsRequired()
                  .HasMaxLength(256);
            
            entity.Property(e => e.PasswordHash)
                  .IsRequired()
                  .HasMaxLength(256);
            
            entity.Property(e => e.FirstName)
                  .IsRequired()
                  .HasMaxLength(100);
            
            entity.Property(e => e.LastName)
                  .IsRequired()
                  .HasMaxLength(100);
            
            entity.Property(e => e.PasswordResetToken)
                  .HasMaxLength(256);
            
            entity.Property(e => e.EmailVerificationToken)
                  .HasMaxLength(256);
            
            entity.Property(e => e.CreatedAt)
                  .HasDefaultValueSql("CURRENT_TIMESTAMP");
            
            entity.Property(e => e.UpdatedAt)
                  .HasDefaultValueSql("CURRENT_TIMESTAMP");
        });
    }
    
    public override int SaveChanges()
    {
        UpdateTimestamps();
        return base.SaveChanges();
    }
    
    public override async Task<int> SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        UpdateTimestamps();
        return await base.SaveChangesAsync(cancellationToken);
    }
    
    private void UpdateTimestamps()
    {
        var entries = ChangeTracker.Entries()
            .Where(e => e.Entity is User && (e.State == EntityState.Added || e.State == EntityState.Modified));
        
        foreach (var entityEntry in entries)
        {
            var user = (User)entityEntry.Entity;
            
            if (entityEntry.State == EntityState.Added)
            {
                user.CreatedAt = DateTime.UtcNow;
            }
            
            user.UpdatedAt = DateTime.UtcNow;
        }
    }
}