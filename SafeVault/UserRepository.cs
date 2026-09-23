using Microsoft.Data.Sqlite;

namespace SafeVault;

public sealed class UserRepository(string connectionString)
{
    private SqliteConnection Open()
    {
        var connection = new SqliteConnection(connectionString);
        connection.Open();
        return connection;
    }

    public void Initialize()
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            CREATE TABLE IF NOT EXISTS Users (
                UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL UNIQUE CHECK(length(Username) BETWEEN 3 AND 100),
                Email TEXT NOT NULL CHECK(length(Email) BETWEEN 3 AND 100)
            );
            """;
        command.ExecuteNonQuery();
    }

    public void Add(string? username, string? email)
    {
        if (!InputValidation.TryValidate(username, email, out var input))
            throw new ArgumentException("Invalid username or email.");
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "INSERT INTO Users (Username, Email) VALUES (@username, @email)";
        command.Parameters.Add("@username", SqliteType.Text).Value = input!.Username;
        command.Parameters.Add("@email", SqliteType.Text).Value = input.Email;
        command.ExecuteNonQuery();
    }

    public UserInput? FindByUsername(string username)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT Username, Email FROM Users WHERE Username = @username";
        command.Parameters.Add("@username", SqliteType.Text).Value = username;
        using var reader = command.ExecuteReader();
        return reader.Read() ? new UserInput(reader.GetString(0), reader.GetString(1)) : null;
    }
}
