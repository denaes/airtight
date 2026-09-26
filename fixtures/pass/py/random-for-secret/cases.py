token = secrets.token_urlsafe(32)
otp = secrets.randbelow(900000) + 100000
nonce = secrets.token_bytes(16)
salt = os.urandom(16)
session_id = secrets.token_hex(32)
csrf = secrets.token_urlsafe(32)
