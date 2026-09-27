public void checkServerTrusted(X509Certificate[] certs, String authType) throws CertificateException { throw new CertificateException("Untrusted certificate"); }
public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException { defaultTrustManager.checkServerTrusted(chain, authType); }
HostnameVerifier verifier = new StrictHostnameVerifier();
sf.setHostnameVerifier(SSLSocketFactory.STRICT_HOSTNAME_VERIFIER);
SSLContext context = SSLContext.getDefault();
HostnameVerifier defaultVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
HostnameVerifier verifier = (hostname, session) -> "api.example.com".equals(hostname);
HostnameVerifier verifier = (hostname, session) -> false;
// Avoid using NoopHostnameVerifier.INSTANCE or ALLOW_ALL_HOSTNAME_VERIFIER in production
// Never implement an empty checkServerTrusted(X509Certificate[] certs, String authType) {} method
/* (hostname, session) -> true disables TLS hostname verification */
* new NullHostnameVerifier() should be replaced with default verification
TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
