const agent = new https.Agent({ rejectUnauthorized: false });
axios.get(url, { httpsAgent: new https.Agent({ rejectUnauthorized: false }) });
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
const opts = { rejectUnauthorized : false };
