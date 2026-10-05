# NestJS Security Card

Sources, sinks, authorization architecture, and common failure modes in NestJS applications.

## Sources (Untrusted Input)

- `@Param()`: Route parameters (e.g., `@Param('id')`). Parsed as raw strings unless converted by transformation pipes (`ParseIntPipe`, `ParseUUIDPipe`).
- `@Query()`: URL query string parameters. Untrusted strings; not validated against types unless a DTO and `ValidationPipe` are explicitly applied.
- `@Body()`: Deserialized HTTP request body. Untrusted JSON/form data. By default, NestJS binds the body directly without schema validation or extra property stripping.
- `@Headers()`: HTTP request headers. Client-controlled and easily forged unless stripped or set by a trusted reverse proxy.
- `@UploadedFile()` / `@UploadedFiles()`: Multipart file uploads. Without explicit `ParseFilePipe` size, MIME-type, and extension validators, allows unconstrained uploads and storage exhaustion.
- Microservice payloads (`@Payload()`, `@Ctx()`): Messages received across transports (TCP, Redis, RabbitMQ, Kafka, NATS). Must be treated as untrusted input.

## Dangerous Sinks

- **TypeORM / Prisma query injection**: Raw SQL executed via `dataSource.query()`, `entityManager.query()`, or `prisma.$queryRawUnsafe()` using string interpolation or string concatenation.
- **Dynamic module injection**: Calling dynamic module methods (`forRoot`, `forFeature`) or factory providers using user-controlled parameters.
- **Microservice deserialization / RCE**: Passing untrusted payloads to custom deserializers or serializers in microservice transport configurations.
- **Template injection**: Calling `res.render('view', data)` with untrusted view names or evaluating server-side templates without auto-escaping.
- **System command execution**: Passing request parameters into `child_process.exec()`, `execSync()`, or `spawn({ shell: true })`.

## Authorization & Architecture: Guards, Pipes, and DTOs

NestJS request processing proceeds in a defined pipeline: Middleware -> Guards -> Interceptors -> Pipes -> Route Handler -> Interceptors -> Exception Filters.

1. **Guards (`CanActivate`, `AuthGuard`)**:
   - Guards determine whether a request proceeds to the handler. They have access to `ExecutionContext` (reflecting controller class and method metadata).
   - Global guards should be bound via dependency injection in a module rather than `app.useGlobalGuards()` so they participate in DI:
     ```ts
     {
       provide: APP_GUARD,
       useClass: JwtAuthGuard,
     }
     ```
   - Beware decorator precedence: Method-level `@UseGuards()` appends to class-level guards. If a method requires custom logic, ensure base authentication guards are not unintentionally skipped.
2. **DTOs & `ValidationPipe`**:
   - NestJS controllers do not validate incoming payloads by default. A DTO class without `ValidationPipe` provides TypeScript compile-time types only, offering zero runtime protection.
   - Always configure global `ValidationPipe` with strict property control:
     ```ts
     app.useGlobalPipes(new ValidationPipe({
       whitelist: true,              // Strip properties not present in the DTO
       forbidNonWhitelisted: true,   // Reject requests containing unknown properties with 400
       transform: true,              // Convert payload to actual DTO class instances
       transformOptions: {
         enableImplicitConversion: false, // Prevent loose automatic type coercion
       },
     }));
     ```
   - DTO properties must have explicit decorators from `class-validator` (e.g., `@IsString()`, `@IsInt()`, `@IsNotEmpty()`). Properties lacking decorators are stripped by `whitelist: true`.
3. **Exception Filters (`@Catch()`)**:
   - Unhandled exceptions caught by NestJS's base filter return standard HTTP responses. Custom filters must avoid echoing database driver error messages, SQL queries, or internal stack traces to the client.

## Top 5 Footguns

1. **Missing `whitelist: true` and `forbidNonWhitelisted: true` on `ValidationPipe`**: Without these settings, `ValidationPipe` validates decorated properties but silently allows undeclared properties to pass into the handler. Passing that DTO into `repository.save(dto)` or `repository.create(dto)` results in mass-assignment vulnerabilities where attackers overwrite `role`, `tenantId`, or `verified`.
2. **Raw TypeORM / Prisma queries via string concatenation**: Using `dataSource.query(\`SELECT * FROM users WHERE id = ${id}\`)` or `entityManager.query('SELECT * FROM items WHERE name = ' + name)` bypasses query builders and introduces SQL injection. Always pass parameters via the parameter array: `dataSource.query('SELECT * FROM users WHERE id = $1', [id])`.
3. **Implicit type conversion (`enableImplicitConversion: true`)**: Enabling automatic conversion causes `class-transformer` to guess types based on TypeScript metadata. This leads to subtle bypasses where unexpected types (such as empty objects `{}` or arrays) bypass validation checks or cause type confusion in business logic.
4. **Unguarded microservice and WebSocket endpoints**: Assuming microservice handlers (`@MessagePattern()`, `@EventPattern()`) or WebSockets (`@SubscribeMessage()`) are trusted because they run behind an API gateway. Guards and `ValidationPipe` must be attached to microservice controllers to prevent untrusted internal message spoofing.
5. **Guard ordering and missing `APP_GUARD`**: Applying `@UseGuards(RolesGuard)` without a preceding `AuthGuard` means `req.user` is undefined when `RolesGuard` evaluates, causing either unhandled runtime crashes or failing open if the guard improperly handles null users. Use `APP_GUARD` to enforce authentication globally by default.
