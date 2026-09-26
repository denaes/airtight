app.use(cors({ origin: "*", credentials: true }));
res.setHeader("Access-Control-Allow-Origin", "*");
const corsOptions = { origin: "*", credentials: true };
headers["Access-Control-Allow-Origin"] = "*";
res.header("Access-Control-Allow-Origin", "*");
res.setHeader("Access-Control-Allow-Credentials", "true");
