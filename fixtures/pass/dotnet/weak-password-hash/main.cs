using System;
using System.Security.Cryptography;

public class HashPassTest {
    public void SafeRun(byte[] fileBytes, System.IO.Stream fileStream) {
        var hasher = new PasswordHasher<User>();
        var hash = SHA256.Create().ComputeHash(fileBytes);
        var salt = RandomNumberGenerator.GetBytes(16);
        byte[] checksum = MD5.Create().ComputeHash(fileStream);
        var argon = new Argon2id(password);
    }
}
