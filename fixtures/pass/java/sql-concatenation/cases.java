PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
pstmt.setString(1, userName);
ResultSet rs = statement.executeQuery("SELECT id, name FROM categories");
String message = "Selected " + count + " items from inventory";
String heading = "Update your profile" + suffix;
String path = "/api/v1/orders/" + orderId;
String log = String.format("User %s logged in successfully", userName);
// statement.executeQuery("SELECT * FROM users WHERE name = '" + userName + "'");
/* conn.createStatement().executeUpdate("DELETE FROM orders WHERE id = " + orderId); */
 * stmt.execute("UPDATE accounts SET balance = " + balance + " WHERE id = " + id);
statement.executeQuery("SELECT id, name " + "FROM categories WHERE active = 1");
conn.prepareStatement("UPDATE accounts SET balance = ? WHERE id = ?");
conn.prepareStatement("DELETE FROM orders WHERE id = ?");
