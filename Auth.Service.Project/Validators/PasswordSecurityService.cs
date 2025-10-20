using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;

namespace Auth.Service.Project.Validators;

/// <summary>
/// Strong password validation attribute that enforces complex password requirements
/// </summary>
public class StrongPasswordAttribute : ValidationAttribute
{
    private const int MinLength = 12;
    private const int MaxLength = 128;

    public override bool IsValid(object? value)
    {
        if (value is not string password)
            return false;

        if (string.IsNullOrWhiteSpace(password))
            return false;

        // Length requirements
        if (password.Length < MinLength || password.Length > MaxLength)
        {
            ErrorMessage = $"Password must be between {MinLength} and {MaxLength} characters long.";
            return false;
        }

        // Check for uppercase letter
        if (!password.Any(char.IsUpper))
        {
            ErrorMessage = "Password must contain at least one uppercase letter.";
            return false;
        }

        // Check for lowercase letter
        if (!password.Any(char.IsLower))
        {
            ErrorMessage = "Password must contain at least one lowercase letter.";
            return false;
        }

        // Check for digit
        if (!password.Any(char.IsDigit))
        {
            ErrorMessage = "Password must contain at least one digit.";
            return false;
        }

        // Check for special character
        if (!password.Any(c => "!@#$%^&*()_+-=[]{}|;:,.<>?".Contains(c)))
        {
            ErrorMessage = "Password must contain at least one special character (!@#$%^&*()_+-=[]{}|;:,.<>?).";
            return false;
        }

        // Check for common patterns
        if (ContainsCommonPatterns(password))
        {
            ErrorMessage = "Password contains common patterns that make it weak.";
            return false;
        }

        // Check for sequential characters
        if (ContainsSequentialChars(password))
        {
            ErrorMessage = "Password cannot contain sequential characters (e.g., abc, 123).";
            return false;
        }

        // Check for repeated characters
        if (ContainsRepeatedChars(password))
        {
            ErrorMessage = "Password cannot contain more than 2 consecutive identical characters.";
            return false;
        }

        return true;
    }

    private static bool ContainsCommonPatterns(string password)
    {
        var commonPatterns = new[]
        {
            "password", "pass", "admin", "user", "login", "welcome",
            "123456", "qwerty", "abc", "test", "demo", "temp"
        };

        return commonPatterns.Any(pattern => 
            password.ToLowerInvariant().Contains(pattern));
    }

    private static bool ContainsSequentialChars(string password)
    {
        const string sequences = "abcdefghijklmnopqrstuvwxyz0123456789";
        
        for (int i = 0; i < password.Length - 2; i++)
        {
            var substring = password.Substring(i, 3).ToLowerInvariant();
            if (sequences.Contains(substring) || sequences.Contains(new string(substring.Reverse().ToArray())))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsRepeatedChars(string password)
    {
        for (int i = 0; i < password.Length - 2; i++)
        {
            if (password[i] == password[i + 1] && password[i + 1] == password[i + 2])
            {
                return true;
            }
        }

        return false;
    }
}

/// <summary>
/// Service for password security operations including history and validation
/// </summary>
public interface IPasswordSecurityService
{
    /// <summary>
    /// Validates password strength beyond basic requirements
    /// </summary>
    Task<(bool IsValid, string[] Errors)> ValidatePasswordStrengthAsync(string password, string email);

    /// <summary>
    /// Checks if password has been used recently by the user
    /// </summary>
    Task<bool> IsPasswordRecentlyUsedAsync(Guid userId, string password);

    /// <summary>
    /// Stores password in history for future validation
    /// </summary>
    Task StorePasswordHistoryAsync(Guid userId, string passwordHash);

    /// <summary>
    /// Checks if password appears in common password lists
    /// </summary>
    bool IsCommonPassword(string password);

    /// <summary>
    /// Calculates password entropy/strength score
    /// </summary>
    double CalculatePasswordEntropy(string password);
}

public class PasswordSecurityService : IPasswordSecurityService
{
    private readonly ILogger<PasswordSecurityService> _logger;
    private readonly HashSet<string> _commonPasswords;
    private const int PasswordHistoryLimit = 5; // Remember last 5 passwords

    // In-memory storage for password history (in production, use database)
    private readonly Dictionary<Guid, Queue<string>> _passwordHistory = new();

    public PasswordSecurityService(ILogger<PasswordSecurityService> logger)
    {
        _logger = logger;
        _commonPasswords = LoadCommonPasswords();
    }

    public async Task<(bool IsValid, string[] Errors)> ValidatePasswordStrengthAsync(string password, string email)
    {
        var errors = new List<string>();

        // Check if password contains email parts
        if (ContainsEmailParts(password, email))
        {
            errors.Add("Password cannot contain parts of your email address.");
        }

        // Check entropy/strength
        var entropy = CalculatePasswordEntropy(password);
        if (entropy < 50) // Minimum entropy threshold
        {
            errors.Add("Password is not complex enough. Consider using a longer password with mixed characters.");
        }

        // Check against common passwords
        if (IsCommonPassword(password))
        {
            errors.Add("Password is too common. Please choose a more unique password.");
        }

        // Simulate async operation for future database checks
        await Task.Delay(1);

        return (errors.Count == 0, errors.ToArray());
    }

    public async Task<bool> IsPasswordRecentlyUsedAsync(Guid userId, string password)
    {
        // Simulate async operation
        await Task.Delay(1);

        if (!_passwordHistory.ContainsKey(userId))
            return false;

        var history = _passwordHistory[userId];
        return history.Any(hashedPassword => BCrypt.Net.BCrypt.Verify(password, hashedPassword));
    }

    public async Task StorePasswordHistoryAsync(Guid userId, string passwordHash)
    {
        // Simulate async operation
        await Task.Delay(1);

        if (!_passwordHistory.ContainsKey(userId))
        {
            _passwordHistory[userId] = new Queue<string>();
        }

        var history = _passwordHistory[userId];
        history.Enqueue(passwordHash);

        // Keep only the last N passwords
        while (history.Count > PasswordHistoryLimit)
        {
            history.Dequeue();
        }

        _logger.LogDebug("Password history updated for user {UserId}", userId);
    }

    public bool IsCommonPassword(string password)
    {
        return _commonPasswords.Contains(password.ToLowerInvariant());
    }

    public double CalculatePasswordEntropy(string password)
    {
        if (string.IsNullOrEmpty(password))
            return 0;

        // Calculate character space
        int characterSpace = 0;

        if (password.Any(char.IsLower)) characterSpace += 26;
        if (password.Any(char.IsUpper)) characterSpace += 26;
        if (password.Any(char.IsDigit)) characterSpace += 10;
        if (password.Any(c => "!@#$%^&*()_+-=[]{}|;:,.<>?".Contains(c))) characterSpace += 23;

        // Calculate entropy: log2(characterSpace^length)
        return password.Length * Math.Log2(characterSpace);
    }

    private static bool ContainsEmailParts(string password, string email)
    {
        if (string.IsNullOrEmpty(email))
            return false;

        var emailParts = email.ToLowerInvariant().Split('@');
        var username = emailParts[0];

        // Check if password contains username or significant parts of it
        if (username.Length >= 3)
        {
            var passwordLower = password.ToLowerInvariant();
            
            // Check full username
            if (passwordLower.Contains(username))
                return true;

            // Check username parts (if username is long enough)
            if (username.Length >= 6)
            {
                for (int i = 0; i <= username.Length - 4; i++)
                {
                    var part = username.Substring(i, 4);
                    if (passwordLower.Contains(part))
                        return true;
                }
            }
        }

        return false;
    }

    private static HashSet<string> LoadCommonPasswords()
    {
        // Top 100 most common passwords (in production, load from file or database)
        var commonPasswords = new[]
        {
            "password", "123456", "password123", "admin", "qwerty", "letmein", "welcome",
            "monkey", "1234567890", "123456789", "dragon", "rockyou", "princess", "654321",
            "123123", "liverpool", "flower", "access", "master", "sunshine", "ashley",
            "bailey", "passw0rd", "shadow", "123qwe", "654321", "superman", "qazwsx",
            "michael", "Football", "baseball", "jennifer", "jordan", "abcd1234", "trustno1",
            "hello", "starwars", "computer", "michelle", "Jessica", "pepper", "1111",
            "zxcvbn", "555555", "11111111", "131313", "freedom", "777777", "pass",
            "maggie", "159753", "aaaaaa", "ginger", "princess", "joshua", "cheese",
            "amanda", "summer", "love", "ashley", "6969", "nicole", "chelsea", "biteme",
            "matthew", "access", "yankees", "987654321", "dallas", "austin", "thunder",
            "taylor", "matrix", "william", "corvette", "hello", "martin", "heather",
            "secret", "fucker", "merlin", "diamond", "1234qwer", "gfhjkm", "hammer",
            "silver", "222222", "88888888", "anthony", "justin", "test", "bailey",
            "q1w2e3r4t5", "patrick", "internet", "scooter", "orange", "11111",
            "golfer", "cookie", "richard", "samantha", "bigdog", "guitar", "jackson",
            "whatever", "mickey", "chicken", "sparky", "snoopy", "maverick", "phoenix"
        };

        return new HashSet<string>(commonPasswords, StringComparer.OrdinalIgnoreCase);
    }
}