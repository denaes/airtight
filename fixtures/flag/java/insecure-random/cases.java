// True positive cases for java/insecure-random
import java.util.Random;

public class Cases {
    public void flagCases() {
        // Case 1: Random nextInt used in token string
        String token = "t_" + new Random().nextInt();

        // Case 2: Random nextInt assigned to secret
        int secret = new Random().nextInt();

        // Case 3: Math.random used for apiKey
        String apiKey = "key_" + Math.random();

        // Case 4: java.util.Random nextLong assigned to session
        String session = "s_" + new java.util.Random().nextLong();

        // Case 5: Random nextInt used in passwordResetToken
        String passwordResetToken = "reset_" + new Random().nextInt(1000000);

        // Case 6: Random nextBytes populating salt buffer
        byte[] salt = new byte[16];
        new Random().nextBytes(salt);

        // Case 7: java.util.Random nextDouble used for nonce
        String nonce = String.valueOf(new java.util.Random().nextDouble());
    }
}
