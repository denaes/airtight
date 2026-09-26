obj = json.loads(blob)
data = msgpack.unpackb(raw)
# pickle is not used for untrusted input
store = shelve_like_cache.get(key)
cached = orjson.loads(payload)
up = JsonDecoder(fh).load()
