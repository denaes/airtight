User.find({ _id: req.params.id });
User.find({ username: String(req.body.username) });
db.users.find({ active: true, role: "admin" });
User.find(sanitizedFilter);
collection.find({ $where: function() { return this.active; } });
const whereKey = "$where";
