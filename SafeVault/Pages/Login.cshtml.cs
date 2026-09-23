using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.RateLimiting;

namespace SafeVault.Pages;

[EnableRateLimiting("credentials")]
public class LoginModel(AuthenticationService authentication) : PageModel
{
    public string? Error { get; private set; }
    public IActionResult OnGet() => User.Identity?.IsAuthenticated == true
        ? LocalRedirect("/Dashboard") : Page();

    public async Task<IActionResult> OnPostAsync(string? username, string? password)
    {
        if (User.Identity?.IsAuthenticated == true)
            return LocalRedirect("/Dashboard");

        var account = authentication.Authenticate(username, password);
        if (account is null)
        {
            Response.StatusCode = 401;
            Error = "Invalid username or password.";
            return Page();
        }
        var identity = new ClaimsIdentity(new[]
        {
            new Claim(ClaimTypes.NameIdentifier, account.Id.ToString()),
            new Claim(ClaimTypes.Name, account.Username),
            new Claim(ClaimTypes.Role, account.Role)
        }, CookieAuthenticationDefaults.AuthenticationScheme);
        await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity), new AuthenticationProperties { IsPersistent = false });
        // Fixed local destination avoids open redirects through a supplied return URL.
        return LocalRedirect("/Dashboard");
    }
}

