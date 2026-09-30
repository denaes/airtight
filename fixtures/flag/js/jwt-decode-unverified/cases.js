const decoded = jwt.decode(token);
const payload = jwt.decode(authHeader.split(' ')[1]);
const claims = jwt.decode(req.headers.authorization, { complete: true });
const user = jwt.decode(req.cookies.token);
const data = jwt.decode(idToken);
