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
public class TestInputValidation
{
    [TestCase("alice_1", "alice@example.com")]
    [TestCase(" jane.doe ", " jane+tag@example.co.uk ")]
    [TestCase("oconnor", "o'connor@example.com")]
    public void ValidInputIsNormalized(string username, string email)
    {
        Assert.That(InputValidation.TryValidate(username, email, out var input), Is.True);
        Assert.That(input, Is.EqualTo(new UserInput(username.Trim(), email.Trim())));
    }

    [TestCase("' OR 1=1 --")]
    [TestCase("alice'; DROP TABLE Users;--")]
    [TestCase("<script>alert(1)</script>")]
    [TestCase("<img src=x onerror=alert(1)>")]
    [TestCase("&#60;script&#62;")]
    [TestCase("%3Cscript%3E")]
    [TestCase("alice\0")]
    [TestCase("a\nb")]
    [TestCase("")]
    [TestCase(null)]
    public void RejectsInvalidUsername(string? username) =>
        Assert.That(InputValidation.TryValidate(username, "alice@example.com", out _), Is.False);

    [TestCase("<script>alert(1)</script>@example.com")]
    [TestCase("a@example.com' OR 1=1 --")]
    [TestCase("a@b.com\r\nBcc:evil@example.com")]
    [TestCase("a..b@example.com")]
    [TestCase(".a@example.com")]
    [TestCase("a@-example.com")]
    [TestCase("Alice <alice@example.com>")]
    [TestCase(null)]
    public void RejectsInvalidEmail(string? email) =>
        Assert.That(InputValidation.TryValidate("alice", email, out _), Is.False);

    [Test]
    public void EnforcesLengthBoundaries()
    {
        Assert.That(InputValidation.TryValidate(new string('a', 100), "a@example.com", out _), Is.True);
        Assert.That(InputValidation.TryValidate(new string('a', 101), "a@example.com", out _), Is.False);
        Assert.That(InputValidation.TryValidate("ab", "a@example.com", out _), Is.False);
        Assert.That(InputValidation.TryValidate("alice", new string('a', 65) + "@example.com", out _), Is.False);
        Assert.That(InputValidation.TryValidate("alice", "a@" + new string('b', 95) + ".com", out _), Is.False);
    }
}

[TestFixture]
public class SecurityIntegrationTests
{
    private SqliteConnection keeper = null!;
    private UserRepository repository = null!;
    private WebApplicationFactory<Program> factory = null!;
    private HttpClient client = null!;

    [SetUp]
    public void SetUp()
    {
        var connectionString = $"Data Source=test-{Guid.NewGuid():N};Mode=Memory;Cache=Shared";
        keeper = new SqliteConnection(connectionString);
        keeper.Open();
        repository = new UserRepository(connectionString);
        repository.Initialize();
        repository.Add("alice", "alice@example.com");
        factory = new WebApplicationFactory<Program>().WithWebHostBuilder(builder =>
            builder.ConfigureServices(services =>
            {
                services.RemoveAll<UserRepository>();
                services.AddSingleton(repository);
            }));
        client = factory.CreateClient();
    }

    [TearDown]
    public void TearDown()
    {
        client.Dispose();
        factory.Dispose();
        keeper.Dispose();
    }

    [TestCase("' OR 1=1 --")]
    [TestCase("alice' --")]
    [TestCase("'; DROP TABLE Users; --")]
    [TestCase("' UNION SELECT Username, Email FROM Users --")]
    public void LookupTreatsSqlPayloadAsData(string payload)
    {
        Assert.That(repository.FindByUsername(payload), Is.Null);
        Assert.That(repository.FindByUsername("alice")?.Email, Is.EqualTo("alice@example.com"));
    }

    [Test]
    public void InsertPreservesLegitimateApostrophe()
    {
        repository.Add("oconnor", "o'connor@example.com");
        Assert.That(repository.FindByUsername("oconnor")?.Email, Is.EqualTo("o'connor@example.com"));
    }

    private async Task<HttpResponseMessage> Submit(string username, string email)
    {
        var form = await client.GetStringAsync("/submit");
        var token = Regex.Match(form, "name=\"__RequestVerificationToken\"[^>]*value=\"([^\"]+)\"");
        Assert.That(token.Success, Is.True, "Form must contain an antiforgery token.");
        return await client.PostAsync("/submit", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["username"] = username,
            ["email"] = email,
            ["__RequestVerificationToken"] = WebUtility.HtmlDecode(token.Groups[1].Value)
        }));
    }

    [TestCase("' OR 1=1 --", "x@example.com")]
    [TestCase("x'; DROP TABLE Users; --", "x@example.com")]
    [TestCase("<script>alert(1)</script>", "x@example.com")]
    [TestCase("<img src=x onerror=alert(1)>", "x@example.com")]
    [TestCase("bob", "<svg onload=alert(1)>@example.com")]
    public async Task FormRejectsAttacksWithoutChangingDatabase(string username, string email)
    {
        using var response = await Submit(username, email);
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        var html = await response.Content.ReadAsStringAsync();
        Assert.That(html, Does.Not.Contain(username == "bob" ? email : username));
        using var count = keeper.CreateCommand();
        count.CommandText = "SELECT COUNT(*) FROM Users";
        Assert.That((long)count.ExecuteScalar()!, Is.EqualTo(1));
        Assert.That(repository.FindByUsername("alice"), Is.Not.Null);
    }

    [Test]
    public async Task ValidFormPersistsAndEncodesOutput()
    {
        using var response = await Submit("oconnor", "o'connor@example.com");
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        var html = await response.Content.ReadAsStringAsync();
        Assert.That(html, Does.Contain("o&#x27;connor@example.com"));
        Assert.That(html, Does.Not.Contain("o'connor@example.com"));
        Assert.That(repository.FindByUsername("oconnor"), Is.Not.Null);
        Assert.That(response.Headers.GetValues("Content-Security-Policy").Single(), Does.Contain("default-src 'none'"));
    }

    [Test]
    public async Task MissingAntiforgeryTokenIsRejected()
    {
        using var response = await client.PostAsync("/submit", new FormUrlEncodedContent(new Dictionary<string,string>
        { ["username"] = "bob", ["email"] = "bob@example.com" }));
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        Assert.That(repository.FindByUsername("bob"), Is.Null);
    }

    [Test]
    public async Task DuplicateUserReturnsConflict()
    {
        using var response = await Submit("alice", "other@example.com");
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Conflict));
        Assert.That(repository.FindByUsername("alice")?.Email, Is.EqualTo("alice@example.com"));
    }
}
