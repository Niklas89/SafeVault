using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
namespace SafeVault.Pages;
[Authorize(Roles = "admin")]
public class AdminModel(UserRepository repository) : PageModel
{
    public IReadOnlyList<UserInput> Users { get; private set; } = [];
    public void OnGet() => Users = repository.GetAllUsers();
}
