ctx.verify_mode = ssl.CERT_REQUIRED
conn.cert_reqs = "CERT_REQUIRED"
pool = HTTPSConnectionPool(host, cert_reqs='CERT_REQUIRED', ca_certs=certifi.where())
context.verify_mode = ssl.CERT_OPTIONAL
CERT_NONE_DOC = "pass cert_reqs=CERT_REQUIRED in production"
ctx.load_verify_locations(cafile=certifi.where())
