// False positive cases for rust/tls-insecure-skip-verify

fn pass_cases() {
    // Case 1: Explicitly enabling cert verification (false parameter)
    let _client1 = reqwest::Client::builder()
        .danger_accept_invalid_certs(false)
        .build()
        .unwrap();

    // Case 2: Explicitly enabling hostname verification (false parameter)
    let _client2 = reqwest::Client::builder()
        .danger_accept_invalid_hostnames(false)
        .build()
        .unwrap();

    // Case 3: Default reqwest client with secure defaults
    let _client3 = reqwest::Client::new();

    // Case 4: Standard native-tls connector
    let _connector = native_tls::TlsConnector::new().unwrap();

    // Case 5: Commented out insecure setting
    // let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build();

    // Case 6: Safe custom root CA certificate
    let cert_data = include_bytes!("cert.pem");
    let cert = reqwest::Certificate::from_pem(cert_data).unwrap();
    let _client4 = reqwest::Client::builder().add_root_certificate(cert).build().unwrap();

    // Case 7: Using rustls connector builder safely
    let root_store = rustls::RootCertStore::empty();
    let _config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
}
