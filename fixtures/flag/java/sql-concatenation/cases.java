statement.executeQuery("SELECT * FROM users WHERE name = '" + userName + "'");
conn.createStatement().executeUpdate("DELETE FROM orders WHERE id = " + orderId);
stmt.execute("UPDATE accounts SET balance = " + balance + " WHERE id = " + id);
statement.executeQuery(String.format("SELECT * FROM items WHERE cat = '%s'", category));
String sql = "INSERT INTO users (username, email) VALUES ('" + username + "', '" + email + "')";
PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = " + request.getParameter("id"));
statement.executeLargeUpdate("DELETE FROM cache WHERE expired_at < " + timestamp);
String query = String.format("SELECT id FROM accounts WHERE email = '%s'", email);
