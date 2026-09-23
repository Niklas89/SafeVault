using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using NUnit.Framework;
using SafeVault;

namespace SafeVault.Tests;

[TestFixture]
public class AuthenticationTests
{
    private const string Password = "Correct-password-42!";
    private SqliteConnection keeper = null!;
    private UserRepository repository = null!;
    private WebApplicationFactory<Program> factory = null!;
    private HttpClient client = null!;

    [SetUp]
    public void SetUp()
    {
        var cs = $"Data Source=auth-{Guid.NewGuid():N};Mode=Memory;Cache=Shared;Foreign Keys=True";
        keeper = new SqliteConnection(cs);
        keeper.Open();
        repository = new UserRepository(cs);
        repository.Initialize();
        repository.CreateAccount("member", "member@example.com", Password);
        repository.CreateAccount("administrator", "admin@example.com", Password, "admin");
        factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            builder.UseEnvironment("Development").ConfigureServices(services =>
            {
                services.RemoveAll<UserRepository>();
                services.AddSingleton(repository);
            }));
        client = factory.CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });
    }

    [TearDown]
    public void TearDown()
    {
        client.Dispose();
        factory.Dispose();
        keeper.Dispose();
    }

    private async Task<HttpResponseMessage> Post(string path, Dictionary<string, string> values, string? tokenPage = null)
    {
        var html = await client.GetStringAsync(tokenPage ?? path);
        var token = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
        Assert.That(token.Success, Is.True);
        values["__RequestVerificationToken"] = WebUtility.HtmlDecode(token.Groups[1].Value);
        return await client.PostAsync(path, new FormUrlEncodedContent(values));
    }

    private static string FieldValue(string html, string name)
    {
        var field = Regex.Match(html, $"<input[^>]*name=\"{name}\"[^>]*>");
        Assert.That(field.Success, Is.True);
        var value = Regex.Match(field.Value, "value=\"([^\"]*)\"");
        // Razor omits the value attribute when the model property is null.
        return value.Success ? WebUtility.HtmlDecode(value.Groups[1].Value) : "";
    }
    [TestCase("member", HttpStatusCode.Conflict)]
    [TestCase("\"><script>alert(1)</script>", HttpStatusCode.BadRequest)]
    public async Task RegistrationRetainsFieldsSafelyAndAllowsCorrection(string username, HttpStatusCode expected)
    {
        var values = new Dictionary<string, string>
        {
            ["username"] = username, ["email"] = "o'connor@example.com",
            ["password"] = "Password-with-\"<>&-42!", ["confirmPassword"] = "Password-with-\"<>&-42!"
        };
        using var rejected = await Post("/Register", values);
        Assert.That(rejected.StatusCode, Is.EqualTo(expected));
        var html = await rejected.Content.ReadAsStringAsync();
        foreach (var name in new[] { "username", "email", "password", "confirmPassword" })
            Assert.That(FieldValue(html, name), Is.EqualTo(values[name]));
        Assert.That(html, Does.Not.Contain("<script>"));
        Assert.That(rejected.Headers.CacheControl?.NoStore, Is.True);
        values["username"] = "corrected";
        var token = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
        values["__RequestVerificationToken"] = WebUtility.HtmlDecode(token.Groups[1].Value);
        using var corrected = await client.PostAsync("/Register", new FormUrlEncodedContent(values));
        Assert.That(corrected.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var success = await corrected.Content.ReadAsStringAsync();
        foreach (var name in new[] { "username", "email", "password", "confirmPassword" })
            Assert.That(FieldValue(success, name), Is.Empty);
        Assert.That(new AuthenticationService(repository).Authenticate("corrected", values["password"]), Is.Not.Null);
    }
    private Task<HttpResponseMessage> Login(string username, string password = Password) =>
        Post("/Login", new() { ["username"] = username, ["password"] = password });

    [Test]
    public void ActivityOneDatabaseUpgradesWithoutLosingRecords()
    {
        var cs = $"Data Source=upgrade-{Guid.NewGuid():N};Mode=Memory;Cache=Shared;Foreign Keys=True";
        using var oldDatabase = new SqliteConnection(cs);
        oldDatabase.Open();
        using var command = oldDatabase.CreateCommand();
        command.CommandText = """
            CREATE TABLE Users (UserID INTEGER PRIMARY KEY AUTOINCREMENT, Username TEXT NOT NULL UNIQUE, Email TEXT NOT NULL);
            INSERT INTO Users (Username, Email) VALUES ('original', 'original@example.com');
            """;
        command.ExecuteNonQuery();
        var upgraded = new UserRepository(cs);
        upgraded.Initialize();
        upgraded.Initialize();
        Assert.That(upgraded.FindByUsername("original")?.Email, Is.EqualTo("original@example.com"));
        Assert.That(upgraded.FindAccount("original"), Is.Null);
        upgraded.CreateAccount("newaccount", "new@example.com", Password);
        Assert.That(new AuthenticationService(upgraded).Authenticate("newaccount", Password)?.Role, Is.EqualTo("user"));
    }

    [Test]
    public async Task ProductionCookieRequiresHttps()
    {
        using var production = factory.WithWebHostBuilder(builder => builder.UseEnvironment("Production"));
        using var https = production.CreateClient(new WebApplicationFactoryClientOptions
        { AllowAutoRedirect = false, BaseAddress = new Uri("https://localhost") });
        var html = await https.GetStringAsync("/Login");
        var token = Regex.Match(html, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
        using var response = await https.PostAsync("/Login", new FormUrlEncodedContent(new Dictionary<string,string>
        {
            ["username"] = "member", ["password"] = Password,
            ["__RequestVerificationToken"] = WebUtility.HtmlDecode(token.Groups[1].Value)
        }));
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        var cookie = response.Headers.GetValues("Set-Cookie").Single(x => x.StartsWith("SafeVault.Session="));
        Assert.That(cookie.ToLowerInvariant(), Does.Contain("secure").And.Contain("httponly"));
        using var dashboard = await https.GetAsync("/Dashboard");
        Assert.That(dashboard.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }
    [TestCase("member")]
    [TestCase("administrator")]
    public async Task ValidCredentialsCreateSession(string username)
    {
        using var response = await Login(username);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(response.Headers.Location?.OriginalString, Is.EqualTo("/Dashboard"));
        var cookie = response.Headers.GetValues("Set-Cookie").Single(x => x.StartsWith("SafeVault.Session="));
        Assert.That(cookie.ToLowerInvariant(), Does.Contain("httponly").And.Contain("samesite=strict"));
        Assert.That(cookie, Does.Not.Contain(Password));
        using var dashboard = await client.GetAsync("/Dashboard");
        Assert.That(dashboard.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [TestCase("member")]
    [TestCase("administrator")]
    public async Task SignedInVisitorIsRedirectedFromLogin(string username)
    {
        using var login = await Login(username);
        // Repeated GETs cover direct navigation and refreshing the login URL.
        for (var visit = 0; visit < 2; visit++)
        {
            using var response = await client.GetAsync("/Login?ReturnUrl=https://example.com");
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
            Assert.That(response.Headers.Location?.OriginalString, Is.EqualTo("/Dashboard"));
        }
        using var post = await Post("/Login", new()
        { ["username"] = "unknown", ["password"] = "Wrong-password-42!" }, "/Dashboard");
        Assert.That(post.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(post.Headers.Location?.OriginalString, Is.EqualTo("/Dashboard"));
        using var dashboard = await client.GetAsync("/Dashboard");
        Assert.That(dashboard.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(await dashboard.Content.ReadAsStringAsync(), Does.Contain(username));
    }

    [Test]
    public async Task AnonymousVisitorCanViewLogin()
    {
        using var response = await client.GetAsync("/Login");
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(await response.Content.ReadAsStringAsync(), Does.Contain("Sign in to SafeVault"));
    }
    [TestCase("member", "Wrong-password-42!")]
    [TestCase("unknown", Password)]
    [TestCase("' OR 1=1 --", Password)]
    [TestCase("<script>alert(1)</script>", Password)]
    [TestCase("member", "")]
    public async Task InvalidLoginDoesNotCreateSession(string username, string password)
    {
        using var response = await Login(username, password);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(await response.Content.ReadAsStringAsync(), Does.Contain("Invalid username or password."));
        Assert.That(response.Headers.TryGetValues("Set-Cookie", out var values)
            && values.Any(x => x.StartsWith("SafeVault.Session=")), Is.False);
        using var dashboard = await client.GetAsync("/Dashboard");
        Assert.That(dashboard.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
    }

    [TestCase("/Dashboard")]
    [TestCase("/Admin")]
    [TestCase("/submit")]
    public async Task AnonymousVisitorIsSentToLogin(string path)
    {
        using var response = await client.GetAsync(path);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(response.Headers.Location?.OriginalString, Does.Contain("/Login"));
    }

    [TestCase("member", HttpStatusCode.Forbidden)]
    [TestCase("administrator", HttpStatusCode.OK)]
    public async Task AdminRouteChecksServerAssignedRole(string username, HttpStatusCode expected)
    {
        using var login = await Login(username);
        using var response = await client.GetAsync("/Admin?role=admin");
        Assert.That(response.StatusCode, Is.EqualTo(expected));
        if (expected == HttpStatusCode.Forbidden)
            Assert.That(await response.Content.ReadAsStringAsync(), Does.Not.Contain("Administrator access granted"));
    }

    [Test]
    public async Task RegistrationCannotAssignAdminRole()
    {
        using var response = await Post("/Register", new()
        {
            ["username"] = "newmember", ["email"] = "new@example.com", ["password"] = Password,
            ["confirmPassword"] = Password, ["role"] = "admin"
        });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        Assert.That(repository.FindAccount("newmember")?.Role, Is.EqualTo("user"));
        using var login = await Login("newmember");
        using var admin = await client.GetAsync("/Admin");
        Assert.That(admin.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
    }

    [Test]
    public void PasswordsAreSaltedHashesAndLegacyRecordsCannotLogin()
    {
        var member = repository.FindAccount("member")!;
        var admin = repository.FindAccount("administrator")!;
        Assert.That(member.PasswordHash, Is.Not.EqualTo(Password).And.Not.EqualTo(admin.PasswordHash));
        Assert.That(PasswordSecurity.Verify(Password, member.PasswordHash), Is.True);
        Assert.That(PasswordSecurity.Verify("Wrong-password-42!", member.PasswordHash), Is.False);
        repository.Add("legacy", "legacy@example.com");
        repository.Initialize(); // Upgrade/startup is repeatable and preserves existing data.
        Assert.That(repository.FindByUsername("legacy"), Is.Not.Null);
        Assert.That(new AuthenticationService(repository).Authenticate("legacy", Password), Is.Null);
    }

    [TestCase("short", "short")]
    [TestCase(Password, "Different-password-42!")]
    public async Task RegistrationRejectsInvalidPasswords(string password, string confirmation)
    {
        using var response = await Post("/Register", new()
        {
            ["username"] = "newmember", ["email"] = "new@example.com",
            ["password"] = password, ["confirmPassword"] = confirmation
        });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(repository.FindByUsername("newmember"), Is.Null);
    }

    [Test]
    public void PasswordLimitsPreventBcryptTruncation()
    {
        Assert.That(PasswordSecurity.IsValid(new string('a', 72)), Is.True);
        Assert.That(PasswordSecurity.IsValid(new string('a', 73)), Is.False);
        Assert.That(PasswordSecurity.IsValid(new string('é', 37)), Is.False);
        Assert.That(PasswordSecurity.IsValid("Long-password\0-42!"), Is.False);
        Assert.That(new AuthenticationService(repository).Authenticate("member", Password + " "), Is.Null);
    }

    [TestCase("/Login")]
    [TestCase("/Register")]
    public async Task CredentialFormsRequireCsrfToken(string path)
    {
        using var response = await client.PostAsync(path, new FormUrlEncodedContent(new Dictionary<string,string>
        { ["username"] = "member", ["password"] = Password }));
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task LogoutRequiresCsrfAndRemovesBrowserSession()
    {
        using var login = await Login("member");
        using var get = await client.GetAsync("/Logout");
        Assert.That(get.StatusCode, Is.EqualTo(HttpStatusCode.MethodNotAllowed));
        using var forged = await client.PostAsync("/Logout", new FormUrlEncodedContent(new Dictionary<string,string>()));
        Assert.That(forged.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        using var response = await Post("/Logout", new(), "/Dashboard");
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        using var dashboard = await client.GetAsync("/Dashboard");
        Assert.That(dashboard.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
    }

    [Test]
    public async Task TamperedSessionIsRejected()
    {
        using var isolated = factory.CreateClient(new WebApplicationFactoryClientOptions
        { AllowAutoRedirect = false, HandleCookies = false });
        isolated.DefaultRequestHeaders.Add("Cookie", "SafeVault.Session=forged-admin-cookie");
        using var response = await isolated.GetAsync("/Admin");
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
    }

    [Test]
    public async Task LoginRateLimitIsEnforced()
    {
        for (var attempt = 0; attempt < 10; attempt++)
        {
            using var response = await client.GetAsync("/Login");
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        }
        using var blocked = await client.GetAsync("/Login");
        Assert.That(blocked.StatusCode, Is.EqualTo(HttpStatusCode.TooManyRequests));
    }

    [Test]
    public async Task DuplicateRegistrationDoesNotChangePasswordOrRole()
    {
        var previous = repository.FindAccount("member");
        using var response = await Post("/Register", new()
        {
            ["username"] = "member", ["email"] = "other@example.com",
            ["password"] = "Replacement-password-42!", ["confirmPassword"] = "Replacement-password-42!"
        });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
        Assert.That(repository.FindAccount("member"), Is.EqualTo(previous));
    }
}





