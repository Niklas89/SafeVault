using System.Security.Claims;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Data.Sqlite;

namespace SafeVault.Pages;

public class IndexModel(UserRepository repository) : PageModel
{
    public string? Message { get; private set; }

    public void OnPost(string? username, string? email)
    {
        if (!InputValidation.TryValidate(username, email, out var input))
        {
            Response.StatusCode = 400;
            Message = "Enter a username of 3–100 letters, digits, dots, underscores or hyphens, and a valid email of at most 100 characters.";
            return;
        }
        if (!long.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var ownerId))
        {
            Response.StatusCode = 401;
            return;
        }
        try
        {
            repository.Add(input!.Username, input.Email, ownerId);
            Message = $"Saved {input.Username} ({input.Email}).";
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            Response.StatusCode = 409;
            Message = "Unable to save this user. Choose another username.";
        }
    }
}

