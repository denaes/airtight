const safe = zlib.gunzipSync(buffer, { maxOutputLength: 10 * 1024 * 1024 });
const data = zlib.brotliDecompressSync(raw, { maxOutputLength: 5 * 1024 * 1024 });
zlib.gunzip(userBuffer, { maxOutputLength: 1048576 }, (err, decoded) => {});
const stream = zlib.createGunzip();
const compressed = zlib.gzipSync(buffer);
const brotli = zlib.brotliCompressSync(data);
// const uncompressed = zlib.gunzipSync(buffer);
const inflated = zlib.inflateSync(buf, { maxOutputLength: 50 * 1024 * 1024 });
