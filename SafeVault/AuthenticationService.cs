using System.Text;

namespace SafeVault;

public static class PasswordSecurity
{
    public static bool IsValid(string? password) => password is not null
        && password.Length >= 12 && !password.Contains('\0')
        && Encoding.UTF8.GetByteCount(password) <= 72;

    public static string Hash(string password)
    {
        if (!IsValid(password))
            throw new ArgumentException("Use at least 12 characters and at most 72 UTF-8 bytes.");
        return BCrypt.Net.BCrypt.HashPassword(password, workFactor: 12);
    }

    public static bool Verify(string password, string hash) => BCrypt.Net.BCrypt.Verify(password, hash);
}

public sealed record Account(long Id, string Username, string Role, string PasswordHash);

public sealed class AuthenticationService(UserRepository repository)
{
    // A real bcrypt comparison is also performed for unknown users.
    private static readonly string DummyHash = PasswordSecurity.Hash("Dummy-account-password-42!");

    public Account? Authenticate(string? username, string? password)
    {
        if (username is null || username.Length > 200 || !PasswordSecurity.IsValid(password))
            return null;
        var account = repository.FindAccount(username.Trim());
        var valid = PasswordSecurity.Verify(password!, account?.PasswordHash ?? DummyHash);
        return valid ? account : null;
    }
}
