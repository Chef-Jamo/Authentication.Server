using Microsoft.AspNetCore.DataProtection;
using System.Security.Cryptography;
using System.Text;
using Auth.Service.Project.Models;

namespace Auth.Service.Project.Services;

/// <summary>
/// Service for encrypting sensitive data at rest
/// </summary>
public interface IDataProtectionService
{
    /// <summary>
    /// Encrypts sensitive string data
    /// </summary>
    string EncryptString(string plainText, string purpose);

    /// <summary>
    /// Decrypts sensitive string data
    /// </summary>
    string DecryptString(string encryptedText, string purpose);

    /// <summary>
    /// Encrypts sensitive data with time-based expiration
    /// </summary>
    string EncryptStringWithExpiration(string plainText, string purpose, TimeSpan expiration);

    /// <summary>
    /// Decrypts time-based encrypted data (returns null if expired)
    /// </summary>
    string? DecryptStringWithExpiration(string encryptedText, string purpose);

    /// <summary>
    /// Creates a secure hash of sensitive data for comparison
    /// </summary>
    string CreateSecureHash(string data, string salt);

    /// <summary>
    /// Verifies a secure hash
    /// </summary>
    bool VerifySecureHash(string data, string salt, string hash);
}

public class DataProtectionService : IDataProtectionService
{
    private readonly IDataProtector _dataProtector;
    private readonly ITimeLimitedDataProtector _timeLimitedDataProtector;
    private readonly ILogger<DataProtectionService> _logger;

    public DataProtectionService(IDataProtectionProvider dataProtectionProvider, ILogger<DataProtectionService> logger)
    {
        _dataProtector = dataProtectionProvider.CreateProtector("Auth.Service.Project.SensitiveData");
        _timeLimitedDataProtector = _dataProtector.ToTimeLimitedDataProtector();
        _logger = logger;
    }

    public string EncryptString(string plainText, string purpose)
    {
        if (string.IsNullOrEmpty(plainText))
            return string.Empty;

        try
        {
            var purposeProtector = _dataProtector.CreateProtector(purpose);
            return purposeProtector.Protect(plainText);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error encrypting data for purpose: {Purpose}", purpose);
            throw;
        }
    }

    public string DecryptString(string encryptedText, string purpose)
    {
        if (string.IsNullOrEmpty(encryptedText))
            return string.Empty;

        try
        {
            var purposeProtector = _dataProtector.CreateProtector(purpose);
            return purposeProtector.Unprotect(encryptedText);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error decrypting data for purpose: {Purpose}", purpose);
            throw;
        }
    }

    public string EncryptStringWithExpiration(string plainText, string purpose, TimeSpan expiration)
    {
        if (string.IsNullOrEmpty(plainText))
            return string.Empty;

        try
        {
            var purposeProtector = _timeLimitedDataProtector.CreateProtector(purpose);
            return purposeProtector.Protect(plainText, expiration);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error encrypting data with expiration for purpose: {Purpose}", purpose);
            throw;
        }
    }

    public string? DecryptStringWithExpiration(string encryptedText, string purpose)
    {
        if (string.IsNullOrEmpty(encryptedText))
            return null;

        try
        {
            var purposeProtector = _timeLimitedDataProtector.CreateProtector(purpose);
            return purposeProtector.Unprotect(encryptedText);
        }
        catch (CryptographicException)
        {
            // Token expired or invalid
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error decrypting time-limited data for purpose: {Purpose}", purpose);
            return null;
        }
    }

    public string CreateSecureHash(string data, string salt)
    {
        if (string.IsNullOrEmpty(data))
            return string.Empty;

        try
        {
            using var pbkdf2 = new Rfc2898DeriveBytes(data, Encoding.UTF8.GetBytes(salt), 100000, HashAlgorithmName.SHA256);
            var hash = pbkdf2.GetBytes(32);
            return Convert.ToBase64String(hash);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error creating secure hash");
            throw;
        }
    }

    public bool VerifySecureHash(string data, string salt, string hash)
    {
        if (string.IsNullOrEmpty(data) || string.IsNullOrEmpty(hash))
            return false;

        try
        {
            var computedHash = CreateSecureHash(data, salt);
            return computedHash == hash;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error verifying secure hash");
            return false;
        }
    }
}

/// <summary>
/// Enhanced user model with encrypted sensitive data
/// </summary>
public static class UserExtensions
{
    /// <summary>
    /// Encrypts sensitive user data before storing
    /// </summary>
    public static void EncryptSensitiveData(this User user, IDataProtectionService dataProtectionService)
    {
        // Encrypt email verification token if present
        if (!string.IsNullOrEmpty(user.EmailVerificationToken))
        {
            user.EmailVerificationToken = dataProtectionService.EncryptString(
                user.EmailVerificationToken, "EmailVerification");
        }

        // Encrypt password reset token if present
        if (!string.IsNullOrEmpty(user.PasswordResetToken))
        {
            user.PasswordResetToken = dataProtectionService.EncryptString(
                user.PasswordResetToken, "PasswordReset");
        }
    }

    /// <summary>
    /// Decrypts sensitive user data after retrieving
    /// </summary>
    public static void DecryptSensitiveData(this User user, IDataProtectionService dataProtectionService)
    {
        // Decrypt email verification token if present
        if (!string.IsNullOrEmpty(user.EmailVerificationToken))
        {
            try
            {
                user.EmailVerificationToken = dataProtectionService.DecryptString(
                    user.EmailVerificationToken, "EmailVerification");
            }
            catch
            {
                // If decryption fails, token is invalid
                user.EmailVerificationToken = null;
                user.EmailVerificationTokenExpiry = null;
            }
        }

        // Decrypt password reset token if present
        if (!string.IsNullOrEmpty(user.PasswordResetToken))
        {
            try
            {
                user.PasswordResetToken = dataProtectionService.DecryptString(
                    user.PasswordResetToken, "PasswordReset");
            }
            catch
            {
                // If decryption fails, token is invalid
                user.PasswordResetToken = null;
                user.PasswordResetTokenExpiry = null;
            }
        }
    }
}