// True positive cases for java/cors-wildcard
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.servlet.config.annotation.CorsRegistration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;

public class Cases {
    // Case 1: @CrossOrigin annotation with wildcard origin and credentials true
    @CrossOrigin(origins = "*", allowCredentials = "true")
    public void endpointOne() {}

    public void flagCases(CorsRegistration cors, CorsRegistry registry) {
        // Case 2: allowedOrigins then allowCredentials
        cors.allowedOrigins("*").allowCredentials(true);

        // Case 3: registry chain with addMapping, allowedOrigins wildcard, and allowCredentials true
        registry.addMapping("/**").allowedOrigins("*").allowCredentials(true);

        // Case 4: allowCredentials first then allowedOrigins wildcard
        cors.allowCredentials(true).allowedOrigins("*");
    }
}
