h = hashlib.md5(password.encode()).hexdigest()
h2 = hashlib.sha1(passwd.encode()).hexdigest()
stored = hashlib.sha256(password.encode() + salt).hexdigest()
digest = hashlib.sha512(passphrase.encode()).digest()
