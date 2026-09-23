using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;
namespace SafeVault.Pages;
[Authorize]
public class DashboardModel : PageModel { }
