const q = "SELECT * FROM users WHERE name = $1";
const label = "Selected " + count + " items";
const path = "/api/users/" + id;
db.query("SELECT * FROM users WHERE id = ?", [id]);
const msg = "WHERE do you want to go today";
const heading = "Update your profile" + suffix;
