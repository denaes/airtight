// False positive cases for java/cors-wildcard
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.servlet.config.annotation.CorsRegistration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;

public class Cases {
    // Case 1: @CrossOrigin with specific origin and allowCredentials true
    @CrossOrigin(origins = "https://app.com", allowCredentials = "true")
    public void safeEndpointOne() {}

    // Case 2: @CrossOrigin with wildcard origin but allowCredentials false
    @CrossOrigin(origins = "*", allowCredentials = "false")
    public void safeEndpointTwo() {}

    public void passCases(CorsRegistration cors, CorsRegistry registry) {
        // Case 3: Explicit trusted domain with credentials enabled
        cors.allowedOrigins("https://example.com").allowCredentials(true);

        // Case 4: Wildcard origin with credentials explicitly disabled
        cors.allowedOrigins("*").allowCredentials(false);

        // Case 5: Commented out wildcard origin with credentials
        // cors.allowedOrigins("*").allowCredentials(true);

        // Case 6: Allowed origins wildcard without allowCredentials
        cors.allowedOrigins("*");

        // Case 7: Allow credentials true without wildcard origin
        cors.allowCredentials(true);

        // Case 8: Registry mapping with trusted origin and credentials
        registry.addMapping("/**").allowedOrigins("https://trusted.corp").allowCredentials(true);
    }
}
