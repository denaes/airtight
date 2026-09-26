app.use(cors({ origin: allowlist, credentials: true }));
res.setHeader("Access-Control-Allow-Origin", req.headers.origin);
const corsOptions = { origin: ["https://app.example.com"], credentials: true };
res.setHeader("Access-Control-Allow-Credentials", "true");
if (allowlist.includes(origin)) res.setHeader("Access-Control-Allow-Origin", origin);
const credentials = true;
