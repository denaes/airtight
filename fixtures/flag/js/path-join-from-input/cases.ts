const p = path.join(UPLOAD_DIR, req.params.file);
fs.readFileSync(path.resolve(root, req.query.name));
res.sendFile(path.join(__dirname, "files", req.params.id));
createReadStream(path.join(base, req.body.path));
