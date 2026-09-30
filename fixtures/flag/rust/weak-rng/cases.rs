// True positive cases for rust/weak-rng

use rand::Rng;
use rand::distributions::Alphanumeric;

fn flag_cases() {
    // Case 1: thread_rng generating security token
    let token = rand::thread_rng().gen::<[u8; 32]>();

    // Case 2: random() generating sensitive secret
    let secret: u64 = rand::random();

    // Case 3: thread_rng sampling characters for password
    let password = rand::thread_rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect::<String>();

    // Case 4: random() generating apiKey
    let apiKey = format!("{:x}", rand::random::<u128>());

    // Case 5: session token generated with thread_rng
    let session = rand::thread_rng().gen::<[u8; 16]>();

    // Case 6: thread_rng filling auth token buffer
    let mut auth_token = [0u8; 32];
    rand::thread_rng().fill(&mut auth_token);
}
