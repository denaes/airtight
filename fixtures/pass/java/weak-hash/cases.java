MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
String fileChecksum = DigestUtils.sha256Hex(data);
String secureHash = DigestUtils.sha512Hex(payload);
String encodedPassword = new BCryptPasswordEncoder().encode(rawPassword);
Argon2 argon2 = Argon2Factory.create();
// MessageDigest md5 = MessageDigest.getInstance("MD5");
// Avoid using weak hash algorithms like MD5 or SHA-1 for passwords or integrity.
/* MessageDigest sha1 = MessageDigest.getInstance("SHA-1"); */
 * MessageDigest md = MessageDigest.getInstance("md5");
int maxAttempts = 5; // DigestUtils.md5Hex(password);
