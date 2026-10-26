fs.createWriteStream(path.join(outputDir, entry.path));
fs.writeFileSync(path.join(targetFolder, entry.entryName), entry.getData());
entry.pipe(fs.createWriteStream(path.join(extractPath, entry.path)));
fs.writeFile(path.resolve(destDir, file.path), data, cb);
fs.createWriteStream(path.join(dest, header.name));
