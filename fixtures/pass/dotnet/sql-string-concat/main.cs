using System;

public class SqlPassTest {
    public void SafeRun() {
        context.Users.FromSql($"SELECT * FROM Users WHERE Name = {name}");
        context.Users.FromSqlRaw("SELECT * FROM Users WHERE Name = {0}", name);
        context.Users.Where(u => u.Name == name).ToList();
        context.Database.ExecuteSqlRaw("SELECT 1");
        cmd.Parameters.AddWithValue("@id", id);
        // context.Users.FromSqlRaw("SELECT * FROM Users WHERE Name = " + name);
    }
}
