// True positive cases for java/spring-csrf-disabled
package com.example.security;

public class Cases {
    public void configure(HttpSecurity http, HttpSecurity security, HttpSecurity httpSecurity) throws Exception {
        // Case 1: Chained csrf().disable() call on http
        http.csrf().disable();

        // Case 2: Method reference AbstractHttpConfigurer::disable lambda configurer
        http.csrf(AbstractHttpConfigurer::disable);

        // Case 3: Explicit lambda calling csrf.disable()
        http.csrf(csrf -> csrf.disable());

        // Case 4: Chained csrf().disable() call on security variable
        security.csrf().disable();

        // Case 5: Explicit lambda on httpSecurity
        httpSecurity.csrf(csrf -> csrf.disable());
    }

    interface HttpSecurity {
        CsrfConfigurer csrf();
        HttpSecurity csrf(Customizer configurer);
    }

    interface CsrfConfigurer {
        HttpSecurity disable();
    }

    interface Customizer {
    }

    static class AbstractHttpConfigurer {
        public static void disable(Object configurer) {}
    }
}
