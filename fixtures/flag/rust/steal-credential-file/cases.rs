// True positive cases for rust/steal-credential-file
use std::fs::{self, File};

fn flag_cases() {
    // Case 1: read_to_string on private ssh key
    let _ = fs::read_to_string("/home/user/.ssh/id_rsa");

    // Case 2: File::open on AWS credentials
    let _ = File::open("/root/.aws/credentials");

    // Case 3: fs::read on kubeconfig
    let _ = fs::read("/etc/kubernetes/.kube/config");

    // Case 4: File::open on docker config
    let _ = File::open("/home/deploy/.docker/config.json");

    // Case 5: read_to_string on ed25519 ssh key
    let _ = fs::read_to_string("/var/secrets/.ssh/id_ed25519");
}
