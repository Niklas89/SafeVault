using System.Text.RegularExpressions;

namespace SafeVault;

public sealed record UserInput(string Username, string Email);

public static class InputValidation
{
    // Deliberately limited ASCII account names and ordinary ASCII email addresses.
    // Reject invalid input instead of deleting characters and changing its meaning.
    public static bool TryValidate(string? username, string? email, out UserInput? input)
    {
        input = null;
        if (username is null || email is null || username.Length > 200 || email.Length > 200)
            return false;
        username = username.Trim();
        email = email.Trim();
        if (username.Length is < 3 or > 100 || email.Length is < 3 or > 100)
            return false;
        if (!Regex.IsMatch(username, @"\A[A-Za-z0-9_][A-Za-z0-9_.-]*\z", RegexOptions.CultureInvariant))
            return false;
        if (!Regex.IsMatch(email, @"\A[A-Za-z0-9_+.'-]+@[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+\z", RegexOptions.CultureInvariant))
            return false;
        var local = email[..email.IndexOf('@')];
        if (local.Length > 64 || local.StartsWith('.') || local.EndsWith('.') || local.Contains(".."))
            return false;
        input = new UserInput(username, email);
        return true;
    }
}
