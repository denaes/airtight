const safeCors1 = { "Access-Control-Allow-Origin": "https://api.example.com", "Access-Control-Allow-Credentials": "true" };
const safeCors2 = { "Access-Control-Allow-Origin": "https://admin.example.com", "Access-Control-Allow-Credentials": "true" };
headers.set("Access-Control-Allow-Origin", "https://app.example.com");
headers.set("Access-Control-Allow-Credentials", "true");
response.headers.append("Access-Control-Allow-Origin", "https://portal.example.com");
response.headers.append("Access-Control-Allow-Credentials", "true");
const validOrigin = checkOrigin(req.headers.get("Origin"));
headers.set("Access-Control-Allow-Origin", validOrigin);
