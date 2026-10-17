using System;

public class SqlTest {
    public void Run() {
        context.Users.FromSqlRaw("SELECT * FROM Users WHERE Name = '" + name + "'");
        context.Database.ExecuteSqlRaw($"DELETE FROM Logs WHERE Id = {logId}");
        var cmd = new SqlCommand("SELECT * FROM Orders WHERE Id = " + orderId, conn);
        context.Products.FromSqlRaw("SELECT * FROM Products WHERE Cat = " + catId);
    }
}
