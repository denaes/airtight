Algorithm alg = Algorithm.none();
JWTVerifier verifier = JWT.require(Algorithm.none()).build();
Claims claims = Jwts.parser().setSigningKey("").parseClaimsJwt(token).getBody();
Jwts.parserBuilder().build().parseClaimsJwt(untrustedToken);
DefaultJwtParser parser = new DefaultJwtParser(); parser.parseClaimsJwt(jwt);
