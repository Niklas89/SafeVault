using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
namespace SafeVault.Pages;
[Authorize(Roles = "admin")]
public class AdminModel : PageModel { }
