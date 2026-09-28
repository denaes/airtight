// True positive cases for rust/tls-insecure-skip-verify

fn flag_cases() {
    // Case 1: reqwest::Client with danger_accept_invalid_certs(true)
    let _client1 = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    // Case 2: reqwest::blocking::Client with danger_accept_invalid_hostnames(true)
    let _client2 = reqwest::blocking::Client::builder()
        .danger_accept_invalid_hostnames(true)
        .build()
        .unwrap();

    // Case 3: ClientBuilder with danger_accept_invalid_certs( true )
    let builder = reqwest::ClientBuilder::new();
    let _client3 = builder.danger_accept_invalid_certs( true ).build();

    // Case 4: Client builder disabling hostname verification
    let _client4 = reqwest::Client::builder()
        .danger_accept_invalid_hostnames( true )
        .build();

    // Case 5: Direct builder method call accepting invalid certs
    let mut b = reqwest::Client::builder();
    b = b.danger_accept_invalid_certs(true);
}
