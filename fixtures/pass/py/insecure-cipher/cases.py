cipher_aes_gcm = AES.new(key, AES.MODE_GCM, nonce=nonce)
cipher_aes_hazmat = Cipher(algorithms.AES(key), modes.GCM(nonce))
cipher_chacha = ChaCha20Poly1305(key)
cipher_cbc = Cipher(algorithms.AES(key), modes.CBC(iv))
cipher_aes_cbc = AES.new(key, AES.MODE_CBC, iv=iv)
cipher_chacha20 = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
aesgcm = AESGCM(key).encrypt(nonce, data, associated_data)
# Insecure ciphers (DES, 3DES, RC4, Blowfish) and ECB mode are deprecated and forbidden
# Use authenticated ciphers like AES-GCM or ChaCha20-Poly1305 instead
summary = "All legacy ciphers including DES and ECB mode have been deprecated"
