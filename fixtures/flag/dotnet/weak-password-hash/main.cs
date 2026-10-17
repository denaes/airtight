using System;
using System.Security.Cryptography;
using System.Text;

public class HashTest {
    public void Run(string password, byte[] pwdBytes, byte[] userPassword, byte[] passwordBuffer) {
        var hash = MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(password));
        var computed = SHA1.Create().ComputeHash(pwdBytes);
        byte[] userPasswordHash = MD5.Create().ComputeHash(userPassword);
        string passHash = Convert.ToHexString(SHA1.Create().ComputeHash(passwordBuffer));
    }
}
