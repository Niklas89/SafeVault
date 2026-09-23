using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
namespace SafeVault.Pages;
[Authorize]
public class DashboardModel(UserRepository repository) : PageModel
{
    public IReadOnlyList<UserInput> Submissions { get; private set; } = [];
    public IActionResult OnGet()
    {
        if (!long.TryParse(User.FindFirstValue(ClaimTypes.NameIdentifier), out var ownerId))
            return Challenge();
        Submissions = repository.GetSubmissions(ownerId);
        return Page();
    }
}
