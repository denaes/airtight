// True positive cases for rust/env-exfiltration
use std::collections::HashMap;

fn flag_cases() {
    // Case 1: iterating std::env::vars()
    for (k, v) in std::env::vars() {
        println!("{}: {}", k, v);
    }

    // Case 2: collecting env::vars() to hashmap
    let _map: HashMap<String, String> = std::env::vars().collect();

    // Case 3: env::vars without std prefix
    use std::env::vars;
    let dump = vars();

    // Case 4: mapping and filtering vars()
    let _all = std::env::vars().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>();
}
