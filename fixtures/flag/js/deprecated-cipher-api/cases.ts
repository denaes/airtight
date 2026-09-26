const c = crypto.createCipher("aes192", password);
const d = crypto.createDecipher("aes192", password);
return crypto.createCipher(algo, key);
const legacy = crypto.createDecipher("aes-256-cbc", pass);
