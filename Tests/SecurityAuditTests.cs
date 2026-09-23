using System.Net;
using Microsoft.Data.Sqlite;
using NUnit.Framework;
using SafeVault;

namespace SafeVault.Tests;

public partial class AuthenticationTests
{
    [TestCase(false)]
    [TestCase(true)]
    public async Task ChangedOrDeletedAccountCannotReuseOldAdminSession(bool deleteAccount)
    {
        using var login = await Login("administrator");
        using var change = keeper.CreateCommand();
        change.CommandText = deleteAccount
            ? "DELETE FROM Accounts WHERE UserID = @id"
            : "UPDATE Accounts SET Role = 'user' WHERE UserID = @id";
        change.Parameters.AddWithValue("@id", repository.FindAccount("administrator")!.Id);
        change.ExecuteNonQuery();
        using var response = await client.GetAsync("/Admin");
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Redirect));
        Assert.That(response.Headers.Location?.OriginalString, Does.Contain("/Login"));
    }

    [Test]
    public void RepositoryEnforcesOwnershipEvenWhenCallerDisablesForeignKeys()
    {
        var cs = $"Data Source=integrity-{Guid.NewGuid():N};Mode=Memory;Cache=Shared;Foreign Keys=False";
        using var database = new SqliteConnection(cs);
        database.Open();
        var repo = new UserRepository(cs);
        repo.Initialize();
        Assert.Throws<SqliteException>(() => repo.Add("orphan", "orphan@example.com", 999));
        Assert.That(repo.FindByUsername("orphan"), Is.Null, "Failed ownership must roll back the user insert.");
    }

    [TestCase("' OR 1=1 --")]
    [TestCase("'; DROP TABLE Accounts; --")]
    [TestCase("' UNION SELECT 1, Username, 'admin', PasswordHash FROM Accounts JOIN Users USING(UserID) --")]
    public void AccountLookupDoesNotExecuteSqlPayload(string payload)
    {
        Assert.That(repository.FindAccount(payload), Is.Null);
        Assert.That(repository.FindAccount("member")?.Role, Is.EqualTo("user"));
        Assert.That(new AuthenticationService(repository).Authenticate("member", Password), Is.Not.Null);
    }

    [TestCase("' OR 1=1 --", "valid@example.com")]
    [TestCase("validname", "x@example.com'; DROP TABLE Users;--")]
    [TestCase("<svg onload=alert(1)>", "valid@example.com")]
    [TestCase("validname", "\"><img src=x onerror=alert(1)>")]
    [TestCase("&#x3c;script&#x3e;", "valid@example.com")]
    public async Task RegistrationRejectsAttackFieldsWithoutCreatingRecords(string username, string email)
    {
        var before = repository.GetAllUsers().Count;
        using var response = await Post("/Register", new()
        {
            ["username"] = username, ["email"] = email,
            ["password"] = Password, ["confirmPassword"] = Password
        });
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        var html = await response.Content.ReadAsStringAsync();
        Assert.That(FieldValue(html, "username"), Is.EqualTo(username));
        Assert.That(FieldValue(html, "email"), Is.EqualTo(email));
        Assert.That(html, Does.Not.Contain("<svg").And.Not.Contain("<img").And.Not.Contain("<script>"));
        Assert.That(repository.GetAllUsers().Count, Is.EqualTo(before));
    }

    [TestCase("\" autofocus onfocus=alert(1) x=\"")]
    [TestCase("</td><svg onload=alert(1)>")]
    [TestCase("<img src=x onerror=alert(1)>")]
    public async Task HistoricalStoredPayloadsAreEncodedInBothLists(string payload)
    {
        repository.Add("historical", "old@example.com", repository.FindAccount("administrator")!.Id);
        using var command = keeper.CreateCommand();
        command.CommandText = "UPDATE Users SET Username = @payload, Email = @payload WHERE Username = 'historical'";
        command.Parameters.AddWithValue("@payload", payload);
        command.ExecuteNonQuery();
        using var login = await Login("administrator");
        foreach (var path in new[] { "/Admin", "/Dashboard" })
        {
            var html = await client.GetStringAsync(path);
            Assert.That(html, Does.Not.Contain(payload));
            Assert.That(html, Does.Contain(System.Text.Encodings.Web.HtmlEncoder.Default.Encode(payload)));
            Assert.That(html, Does.Not.Contain("<svg").And.Not.Contain("<img"));
        }
    }
}
