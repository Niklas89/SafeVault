using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.Data.Sqlite;
namespace SafeVault.Pages;

[EnableRateLimiting("credentials")]
public class RegisterModel(UserRepository repository) : PageModel
{
    public string? Message { get; private set; }
    public string? Username { get; private set; }
    public string? Email { get; private set; }
    public string? Password { get; private set; }
    public string? ConfirmPassword { get; private set; }
    public IActionResult OnPost(string? username, string? email, string? password, string? confirmPassword)
    {
        // Retain values only for this response; never put passwords in session or storage.
        Username = username;
        Email = email;
        Password = password;
        ConfirmPassword = confirmPassword;
        if (!InputValidation.TryValidate(username, email, out _) || !PasswordSecurity.IsValid(password)
            || password != confirmPassword)
        {
            Response.StatusCode = 400;
            Message = "Check your username and email, and enter the same password twice. Use at least 12 characters. If your password is too long, try a shorter one.";
            return Page();
        }
        try
        {
            // Never bind a role from request data.
            repository.CreateAccount(username, email, password!);
            Message = "Account created. You can now sign in.";
            Username = Email = Password = ConfirmPassword = null;
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            Response.StatusCode = 409;
            Message = "Unable to create this account. Choose another username.";
        }
        return Page();
    }
}


