const dest = path.resolve(outputDir, entry.path);
if (!dest.startsWith(path.resolve(outputDir) + path.sep)) throw new Error('Path traversal detected');
fs.createWriteStream(dest);
// fs.createWriteStream(path.join(outputDir, entry.path));
fs.createWriteStream(path.join(outputDir, 'fixed-filename.txt'));
fs.writeFileSync(path.join(targetDir, 'output.json'), JSON.stringify(data));
const rel = path.relative(outputDir, path.join(outputDir, entry.path));
