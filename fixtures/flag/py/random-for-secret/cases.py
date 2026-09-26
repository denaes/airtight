token = "".join(random.choices(ALPHABET, k=32))
otp = random.randint(100000, 999999)
nonce = random.getrandbits(64)
salt = random.sample(CHARS, 16)
