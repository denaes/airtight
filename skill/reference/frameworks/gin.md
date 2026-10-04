# Gin (Go) Security Card

Sources, sinks, authorization middleware idioms, and common failure modes in Gin Web Framework applications.

## Sources (Untrusted Input)

- `c.Query("name")` / `c.DefaultQuery("name", "val")`: URL query parameters.
- `c.Param("id")`: Route parameters parsed from path definitions (`/users/:id` or `/files/*filepath`).
- `c.PostForm("field")` / `c.MultipartForm()`: Form-encoded fields and file uploads.
- `c.BindJSON(&payload)` / `c.ShouldBindJSON(&payload)` / `c.ShouldBind(&payload)`: Request payload binding into Go structs with validation tags (`binding:"required"`).
- `c.GetHeader("header")`: HTTP request headers.
- `c.Cookie("name")`: Incoming HTTP cookies.
- `c.Request`: Raw `*http.Request` pointer.

## Dangerous Sinks

- **SQL / ORM injection**: Raw queries in GORM (`db.Raw(fmt.Sprintf(...))`, `db.Where(fmt.Sprintf(...))`, `db.Order(userInput)`).
- **Command execution**: `os/exec.Command(cmd, args...)`, `os/exec.CommandContext(...)`.
- **Path traversal / arbitrary file read**: `c.File(path)`, `c.FileAttachment(path, name)`, `http.Dir(path)`.
- **Server-Side Request Forgery (SSRF)**: `http.Get(url)`, `http.Post(url, ...)`, `client.Do(req)` with user-supplied URLs.
- **Open redirect**: `c.Redirect(http.StatusFound, url)` without verifying that the destination host is trusted.

## Authorization Idiom: Middleware Groups

- **Route groups with middleware**:
  ```go
  authorized := r.Group("/api/v1")
  authorized.Use(AuthRequired())
  {
      authorized.GET("/items", ListItems)
      authorized.POST("/items", CreateItem)
  }
  ```
- **The critical `c.Abort()` requirement**:
  - In Gin, returning from a middleware function (`return`) **does not stop handler execution**!
  - If authentication or authorization fails, the middleware **must call `c.Abort()` or `c.AbortWithStatusJSON()`** to halt the middleware and handler execution chain:
    ```go
    func AuthRequired() gin.HandlerFunc {
        return func(c *gin.Context) {
            token := c.GetHeader("Authorization")
            if !validateToken(token) {
                c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
                return // both Abort and return are required
            }
            c.Next()
        }
    }
    ```
- **Context propagation**: Storing authenticated identity or tenant ID in Gin context with `c.Set("tenant_id", tenantID)` and retrieving it safely in route handlers.

## Top 5 Footguns

1. **Missing `c.Abort()` on authentication failure**: Writing `c.JSON(http.StatusUnauthorized, ...); return;` in a middleware function. Gin sends the 401 header, but proceeds to execute every subsequent handler registered on the route, allowing unauthorized operations to execute! Always call `c.Abort()` or `c.AbortWithStatusJSON()`.
2. **SQL Injection in GORM `Where` / `Order`**: Calling `db.Where(fmt.Sprintf("tenant_id = '%s'", tenantID))` or `db.Order(c.Query("sort"))`. GORM parameterizes arguments passed to `db.Where("tenant_id = ?", tenantID)`, but string interpolation or dynamic `Order()` clauses bypass parameterization completely.
3. **Path Traversal via `c.File` and `c.Param`**: Serving files with `c.File(filepath.Join("/var/data", c.Param("filepath")))`. If the route is `/files/*filepath`, `filepath` can contain `../../../../etc/passwd`. `filepath.Join` cleans the path but joins relative to the root unless verified with `strings.HasPrefix(filepath.Clean(fullPath), baseDir)`.
4. **Debug Mode in Production (`gin.SetMode`)**: Failing to set `gin.SetMode(gin.ReleaseMode)` (or omitting the `GIN_MODE=release` environment variable). In default debug mode, Gin logs all route registrations, full request headers, and on uncaught panics (via `gin.Recovery()`) dumps full goroutine stack traces and memory state to the HTTP client.
5. **Unbounded Request Body (Denial of Service)**: Reading or binding request payloads without limiting the maximum request body size. By default, Gin does not cap `c.Request.Body` size; attackers can send multi-gigabyte POST streams to crash the server with an out-of-memory (OOM) panic. Use `c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)` in a global middleware.
