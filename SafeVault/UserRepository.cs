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
            CREATE TABLE IF NOT EXISTS Accounts (
                UserID INTEGER PRIMARY KEY REFERENCES Users(UserID),
                PasswordHash TEXT NOT NULL,
                Role TEXT NOT NULL CHECK(Role IN ('user', 'admin'))
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

    // Called only by registration (fixed user role) or the trusted local admin command.
    public void CreateAccount(string? username, string? email, string password, string role = "user")
    {
        if (!InputValidation.TryValidate(username, email, out var input))
            throw new ArgumentException("Invalid username or email.");
        if (role is not ("user" or "admin"))
            throw new ArgumentException("Invalid role.");
        var hash = PasswordSecurity.Hash(password);
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        using var user = connection.CreateCommand();
        user.Transaction = transaction;
        user.CommandText = "INSERT INTO Users (Username, Email) VALUES (@username, @email) RETURNING UserID";
        user.Parameters.AddWithValue("@username", input!.Username);
        user.Parameters.AddWithValue("@email", input.Email);
        var id = (long)user.ExecuteScalar()!;
        using var account = connection.CreateCommand();
        account.Transaction = transaction;
        account.CommandText = "INSERT INTO Accounts (UserID, PasswordHash, Role) VALUES (@id, @hash, @role)";
        account.Parameters.AddWithValue("@id", id);
        account.Parameters.AddWithValue("@hash", hash);
        account.Parameters.AddWithValue("@role", role);
        account.ExecuteNonQuery();
        transaction.Commit();
    }

    public Account? FindAccount(string username)
    {
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = """
            SELECT u.UserID, u.Username, a.Role, a.PasswordHash
            FROM Users u JOIN Accounts a ON a.UserID = u.UserID
            WHERE u.Username = @username
            """;
        command.Parameters.AddWithValue("@username", username);
        using var reader = command.ExecuteReader();
        return reader.Read() ? new Account(reader.GetInt64(0), reader.GetString(1), reader.GetString(2), reader.GetString(3)) : null;
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

