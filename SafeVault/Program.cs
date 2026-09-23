using Microsoft.Data.Sqlite;
using SafeVault;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddRazorPages();
var dataDirectory = Path.Combine(builder.Environment.ContentRootPath, "App_Data");
Directory.CreateDirectory(dataDirectory);
builder.Services.AddSingleton(new UserRepository(new SqliteConnectionStringBuilder
{
    DataSource = Path.Combine(dataDirectory, "safevault.db")
}.ToString()));
var app = builder.Build();
app.Services.GetRequiredService<UserRepository>().Initialize();
app.UseExceptionHandler("/Error");
app.Use(async (context, next) =>
{
    context.Response.Headers.ContentSecurityPolicy = "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";
    context.Response.Headers.XContentTypeOptions = "nosniff";
    context.Response.Headers.CacheControl = "no-store";
    await next();
});
app.MapRazorPages();
app.Run();

public partial class Program { }
