// False positive cases for java/env-exfiltration
import java.util.Map;

public class Cases {
    public void passCases() {
        // Case 1: Targeted single variable lookup
        String port = System.getenv("PORT");

        // Case 2: Targeted database URL
        String dbUrl = System.getenv("DATABASE_URL");

        // Case 3: Targeted API token
        String apiKey = System.getenv("API_KEY");

        // Case 4: Reading system properties instead of bulk env
        String userHome = System.getProperty("user.home");

        // Case 5: Custom class method named getenv
        CustomConfig cfg = new CustomConfig();
        cfg.getenv();

        // Case 6: Comment referencing System.getenv()
        // Map<String, String> env = System.getenv();
        String activeProfile = System.getProperty("spring.profiles.active");
    }

    static class CustomConfig {
        public void getenv() {}
    }
}
