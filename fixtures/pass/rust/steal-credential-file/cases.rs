// False positive cases for rust/steal-credential-file
use std::fs::{self, File};

fn pass_cases() {
    // Case 1: reading ordinary application config
    let _ = fs::read_to_string("config/settings.toml");

    // Case 2: opening public system host file
    let _ = File::open("/etc/hosts");

    // Case 3: reading local project file
    let _ = fs::read("Cargo.lock");

    // Case 4: opening log file
    let _ = File::open("/var/log/app.log");

    // Case 5: opening regular json payload
    let _ = fs::read_to_string("tests/fixtures/data.json");

    // Case 6: comment mentioning .ssh/id_rsa
    // let path = "/home/user/.ssh/id_rsa";
    let _ = fs::read_to_string("public_key.pub");
}
