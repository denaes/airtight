Cipher cipher1 = Cipher.getInstance("AES/GCM/NoPadding");
Cipher cipher2 = Cipher.getInstance("ChaCha20-Poly1305");
Cipher cipher3 = Cipher.getInstance("AES/CBC/PKCS5Padding");
Cipher cipher4 = Cipher.getInstance("AES/CTR/NoPadding");
Cipher cipher5 = Cipher.getInstance("RSA/None/OAEPWithSHA-256AndMGF1Padding");
Cipher cipher6 = Cipher.getInstance(transformation);
// Insecure ciphers like DES, DESede, RC4, Blowfish and ECB mode are prohibited
// Cipher legacy = Cipher.getInstance("DES");
 * Avoid using Cipher.getInstance("AES/ECB/PKCS5Padding") in production
String policy = "Do not use DES, RC4, Blowfish, or ECB mode in any service";
