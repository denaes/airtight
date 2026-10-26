const uncompressed = zlib.gunzipSync(buffer);
const data = zlib.brotliDecompressSync(raw);
const unpacked = zlib.inflateSync(compressed);
const result = zlib.unzipSync(archivePayload);
zlib.gunzip(userBuffer, (err, decoded) => { handle(decoded); });
brotliDecompressSync(untrustedInput);
