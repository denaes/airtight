const p = path.join(UPLOAD_DIR, path.basename(req.params.file));
const resolved = path.resolve(root, path.basename(req.query.name));
if (!path.normalize(p).startsWith(root)) throw new Error("traversal");
res.sendFile(path.join(__dirname, "files", lookup[req.params.id]));
fs.readFileSync(path.join(CONFIG_DIR, "app.json"));
createReadStream(path.join(base, sanitizePath(name)));
