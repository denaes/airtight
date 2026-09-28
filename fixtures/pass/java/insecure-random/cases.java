// False positive cases for java/insecure-random
import java.security.SecureRandom;
import java.util.Random;

public class Cases {
    public void passCases() {
        // Case 1: SecureRandom used for cryptographically secure random token
        SecureRandom random = new SecureRandom();
        byte[] token = new byte[32];
        random.nextBytes(token);

        // Case 2: Insecure random used for non-sensitive dice roll
        int dice = new Random().nextInt(6);

        // Case 3: Math.random used for non-sensitive percentage
        double pct = Math.random();

        // Case 4: Commented-out line with token and Random
        // String token = "t_" + new Random().nextInt();

        // Case 5: SecureRandom used directly with nextInt for salt
        int saltValue = new SecureRandom().nextInt();

        // Case 6: Non-sensitive game offset using java.util.Random
        java.util.Random rand = new java.util.Random();
        int gameOffset = rand.nextInt(100);

        // Case 7: Secure token generated without insecure PRNG
        String apiKey = System.getenv("API_KEY");
    }
}
