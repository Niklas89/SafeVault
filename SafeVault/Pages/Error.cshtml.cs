using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
namespace SafeVault.Pages;
[IgnoreAntiforgeryToken]
public class ErrorModel : PageModel
{
    public void OnGet() => Response.StatusCode = 500;
    public void OnPost() => Response.StatusCode = 500;
}
