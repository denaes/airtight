ctx.verify_mode = ssl.CERT_NONE
conn.cert_reqs = "CERT_NONE"
pool = HTTPSConnectionPool(host, cert_reqs='CERT_NONE')
context.verify_mode = CERT_NONE
