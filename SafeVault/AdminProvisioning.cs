using System.Text;
using Microsoft.Data.Sqlite;
namespace SafeVault;

public static class AdminProvisioning
{
    public static int Run(UserRepository repository)
    {
        Console.Write("New admin username: ");
        var username = Console.ReadLine();
        Console.Write("Email: ");
        var email = Console.ReadLine();
        Console.Write("Password (hidden): ");
        var password = ReadPassword();
        Console.Write("Confirm password (hidden): ");
        var confirmation = ReadPassword();
        if (password != confirmation)
        {
            Console.WriteLine("Passwords do not match. No account created.");
            return 1;
        }
        try
        {
            repository.CreateAccount(username, email, password, "admin");
            Console.WriteLine("Admin created. Start the application and sign in at /Login.");
            return 0;
        }
        catch (ArgumentException)
        {
            Console.WriteLine("Invalid input. Use a valid username/email and a password of at least 12 characters, at most 72 UTF-8 bytes.");
        }
        catch (SqliteException ex) when (ex.SqliteErrorCode == 19)
        {
            Console.WriteLine("Account not created. Choose an unused username.");
        }
        return 1;
    }

    private static string ReadPassword()
    {
        if (Console.IsInputRedirected) return Console.ReadLine() ?? "";
        var password = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) break;
            if (key.Key == ConsoleKey.Backspace)
            {
                if (password.Length > 0) password.Length--;
            }
            else if (!char.IsControl(key.KeyChar)) password.Append(key.KeyChar);
        }
        Console.WriteLine();
        return password.ToString();
    }
}
