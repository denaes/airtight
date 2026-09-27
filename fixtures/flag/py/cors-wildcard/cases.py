CORS_ALLOW_ALL_ORIGINS = True
CORS_ORIGIN_ALLOW_ALL = True
CORS(app, origins="*")
CORS(app, origins=["*"])
CORS(app, origins=['*'])
cors = CORS(app, allow_headers="*", origins=["*"])
CORS(app, resources={r"/api/*": {"origins": "*"}})
app.add_middleware(CORSMiddleware, allow_origins=["*"])
app.add_middleware(CORSMiddleware, allow_origins="*")
