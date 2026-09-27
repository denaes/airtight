MessageDigest md5Digest = MessageDigest.getInstance("MD5");
MessageDigest sha1Digest = MessageDigest.getInstance("SHA-1");
String passwordHash = DigestUtils.md5Hex(password);
String tokenDigest = DigestUtils.sha1Hex(credential);
MessageDigest md = MessageDigest.getInstance("md5");
MessageDigest legacySha = MessageDigest.getInstance("SHA1");
byte[] rawHash = DigestUtils.md5(data);
byte[] shaBytes = DigestUtils.sha1(payload);
