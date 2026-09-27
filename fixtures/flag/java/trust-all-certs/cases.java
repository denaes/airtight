public void checkServerTrusted(X509Certificate[] certs, String authType) {}
public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException { }
public void checkClientTrusted(X509Certificate[] certs, String authType) { return; }
HostnameVerifier verifier = new NullHostnameVerifier();
HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
builder.setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE);
SSLSocketFactory sf = new SSLSocketFactory(trustStrategy, SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
client.setHostnameVerifier(new AllowAllHostnameVerifier());
SslContext sslCtx = SslContextBuilder.forClient().trustManager(InsecureTrustManagerFactory.INSTANCE).build();
SSLContext sslContext = SSLContextBuilder.create().loadTrustMaterial(TrustAllStrategy.INSTANCE).build();
HostnameVerifier verifier = (hostname, session) -> Boolean.TRUE;
public boolean verify(String hostname, SSLSession session) { return true; }
