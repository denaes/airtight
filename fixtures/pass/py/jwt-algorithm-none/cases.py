jwt.decode(token, secret, algorithms=["HS256"])
jwt.decode(token, public_key, algorithms=["RS256"])
jwt.decode(token, key, options={"verify_signature": True}, algorithms=["ES256"])
jwt.encode(payload, secret, algorithm="HS256")
jwt.decode(token, secret, algorithms=["RS256", "ES256"])
options = {"verify_signature": True}
# Verify JWT token using strong cryptographic algorithms and ensure signatures are verified
# Pin algorithms allowlist and never accept the none algorithm
