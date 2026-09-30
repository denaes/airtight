const verified = jwt.verify(token, secretKey);
jwt.verify(token, secret, cb);
// const decoded = jwt.decode(token);
const verifiedWithOptions = jwt.verify(token, secretKey, { algorithms: ['RS256'] });
const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString());
/* const claims = jwt.decode(token); */
 * const user = jwt.decode(token);
