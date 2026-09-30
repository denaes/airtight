// False positive cases for java/spring-csrf-disabled
package com.example.security;

public class Cases {
    public void configure(HttpSecurity http) throws Exception {
        // Case 1: Chained csrf() call without disable
        http.csrf();

        // Case 2: Custom csrf token repository configuration
        http.csrf(csrf -> csrf.csrfTokenRepository(null));

        // Case 3: Commented out disable call
        // http.csrf().disable();

        // Case 4: Other configurer using AbstractHttpConfigurer::disable (e.g. CORS)
        http.cors(AbstractHttpConfigurer::disable);

        // Case 5: Other configurer lambda disable (e.g. headers)
        http.headers(headers -> headers.disable());

        // Case 6: Enabling CSRF with defaults
        http.csrf(Customizer.withDefaults());

        // Case 7: Selectively ignoring specific endpoints rather than global disable
        http.csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"));
    }

    interface HttpSecurity {
        CsrfConfigurer csrf();
        HttpSecurity csrf(Customizer configurer);
        HttpSecurity cors(Customizer configurer);
        HttpSecurity headers(Customizer configurer);
    }

    interface CsrfConfigurer {
        HttpSecurity csrfTokenRepository(Object repo);
        HttpSecurity ignoringRequestMatchers(String pattern);
    }

    interface Customizer {
        static Customizer withDefaults() { return null; }
    }

    static class AbstractHttpConfigurer {
        public static void disable(Object configurer) {}
    }
}
