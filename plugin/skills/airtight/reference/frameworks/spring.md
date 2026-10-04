# Spring Boot & Spring Security Card

Sources, sinks, authorization architecture, and common failure modes in Spring Boot applications.

## Sources (Untrusted Input)

- `@RequestParam`: Query parameters or form-encoded POST fields.
- `@PathVariable`: Path variables extracted from URI templates (e.g., `/{tenantId}/users/{userId}`).
- `@RequestBody`: Deserialized request body, mapped by Jackson to Java POJOs or DTOs.
- `@RequestHeader`: HTTP request headers.
- `@CookieValue`: HTTP cookies.
- Raw `HttpServletRequest`: `request.getParameter()`, `request.getHeader()`, `request.getInputStream()`.

## Dangerous Sinks

- **Spring Expression Language (SpEL) evaluation**: `SpelExpressionParser.parseExpression(input).getValue(context)`. Dynamic expression evaluation with `StandardEvaluationContext` allows arbitrary code execution.
- **SQL / JPQL injection**: String concatenation in `@Query("... " + param)`, `EntityManager.createQuery(rawSql)`, or `JdbcTemplate.query(rawSql)`.
- **Command execution**: `Runtime.getRuntime().exec()`, `ProcessBuilder.start()`.
- **Insecure deserialization**: Native Java serialization (`ObjectInputStream.readObject()`) or Jackson polymorphic deserialization (`enableDefaultTyping()`, `@JsonTypeInfo(use = Id.CLASS)`).
- **Path traversal**: `ResourceHttpRequestHandler`, `UrlResource`, or serving `FileSystemResource` from user paths.
- **Server-Side Request Forgery (SSRF)**: `RestTemplate`, `WebClient`, or `HttpClient` fetching user-supplied URIs.

## Authorization Idiom: Method Security vs SecurityFilterChain

Spring Security operates at two distinct layers:

1. **`SecurityFilterChain` (URL / Filter layer)**:
   - Configured via `authorizeHttpRequests(auth -> auth.requestMatchers("/admin/**").hasRole("ADMIN").anyRequest().authenticated())`.
   - **Pattern matching pitfalls**: Discrepancies between Spring MVC matching rules and Spring Security filter matchers can cause authorization bypasses (e.g., trailing slashes `/admin` vs `/admin/`, or URI normalization bypasses). Always use `requestMatchers()` (which delegates to Spring MVC's `HandlerMappingIntrospector`) rather than deprecated `antMatchers()`.
2. **Method Security (`@PreAuthorize`, `@PostAuthorize`, `@Secured`)**:
   - Enforces method-level and object-level permissions using SpEL expressions: `@PreAuthorize("hasRole('ADMIN') or #order.tenantId == principal.tenantId")`.
   - Requires `@EnableMethodSecurity` (or legacy `@EnableGlobalMethodSecurity`) in configuration; without this annotation, `@PreAuthorize` annotations are silently ignored at runtime!

## Top 5 Footguns

1. **SpEL Injection via Dynamic Expressions**: Evaluating user-controlled strings in Spring Expression Language: `parser.parseExpression(userInput).getValue(context)`. If evaluated against `StandardEvaluationContext`, attackers achieve full remote code execution via Java reflection (`T(java.lang.Runtime).getRuntime().exec('...')`). Use `SimpleEvaluationContext.forReadOnlyDataBinding().build()` when evaluating user expressions.
2. **Spring Security CSRF disabled (`csrf.disable()`)**: Calling `.csrf(csrf -> csrf.disable())` on state-changing endpoints in applications that authenticate via session cookies or browser HTTP Basic auth. Disabling CSRF is only safe for pure stateless APIs that authenticate exclusively via bearer tokens stored in non-cookie storage.
3. **URL Path Matcher Inconsistencies**: Using loose pattern matching like `requestMatchers("/admin/*")`, which matches `/admin/users` but fails to match `/admin/users/delete` or `/admin/sub/paths`. Use double wildcards (`"/admin/**"`).
4. **Mass Assignment / Direct Entity Binding via `@RequestBody`**: Binding incoming JSON payloads directly to `@Entity` JPA classes in controller parameters: `@PostMapping public User create(@RequestBody User user)`. Attackers include `"id"`, `"roles": ["ROLE_ADMIN"]`, or `"balance"` in the JSON, which Jackson deserializes and JPA persists. Always use dedicated request DTOs.
5. **Path Traversal via Static Resource Handlers**: Misconfiguring `ResourceHandlerRegistry.addResourceLocations()` with file system locations: `registry.addResourceHandler("/files/**").addResourceLocations("file:/var/uploads/")`. If path normalization is mishandled, attackers access arbitrary files on the server with `/files/../../../../etc/passwd`.
