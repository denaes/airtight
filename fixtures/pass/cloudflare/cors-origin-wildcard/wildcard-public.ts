const publicCors = { "Access-Control-Allow-Origin": "*" };
headers.set("Access-Control-Allow-Origin", "*");
response.headers.append("Access-Control-Allow-Origin", "*");
const raw = "Access-Control-Allow-Origin: *";
headers.set("Access-Control-Allow-Credentials", "false");
