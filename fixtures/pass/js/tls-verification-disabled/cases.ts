const agent = new https.Agent({ rejectUnauthorized: true });
const agent2 = new https.Agent({ ca: fs.readFileSync("internal-ca.pem") });
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1";
axios.get(url);
const opts = { timeout: 5000 };
// certificate verification stays on in every environment
