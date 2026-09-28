Algorithm alg = Algorithm.HMAC256("secret");
Algorithm rsa = Algorithm.RSA256(publicKey, privateKey);
Claims claims = Jwts.parser().setSigningKey(key).parseClaimsJws(token).getBody();
Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
Algorithm ecdsa = Algorithm.ECDSA256(ecPublicKey, ecPrivateKey);
// Algorithm.none() is insecure and must not be used
// Claims claims = parser.parseClaimsJwt(token);
