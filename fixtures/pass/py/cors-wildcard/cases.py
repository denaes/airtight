# Safe CORS policies: explicit allowed domains
CORS_ALLOW_ALL_ORIGINS = False
CORS_ORIGIN_ALLOW_ALL = False
CORS_ALLOWED_ORIGINS = ["https://example.com", "https://app.example.com"]
CORS(app, origins=["https://app.example.com"])
CORS(app, origins="https://example.com")
CORS(app, resources={r"/api/*": {"origins": "https://api.example.com"}})
cors = CORS(app, allow_headers="*", origins=["https://api.example.com"])
CORS(app, allow_methods=["*"], origins=["https://example.com"])
app.add_middleware(CORSMiddleware, allow_origins=["https://trusted.domain.com"])
allow_origins = []
is_allowed = origin in allowed_origins
