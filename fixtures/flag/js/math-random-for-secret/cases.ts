const token = Math.random().toString(36).slice(2);
const nonce = String(Math.random());
const otp = Math.floor(Math.random() * 1000000);
const sessionId = `${Date.now()}-${Math.random()}`;
