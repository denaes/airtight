const user = await User.findOne(req.query);
const items = await db.collection("orders").find(req.body);
db.users.find({ $where: "this.name == '" + req.query.name + "'" });
collection.find({ $where: `this.active && this.id == ${req.params.id}` });
User.find({ username: { $regex: req.query.prefix } });
collection.updateOne({ $where: req.body.code }, { $set: { active: true } });
