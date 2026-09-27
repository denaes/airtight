Command::new("git").arg("status");
Command::new("cargo").args(["build", "--release"]);
Command::new("sh").arg("-c").arg("echo static");
Command::new("bash").args(["-c", "echo literal"]);
Command::new("echo").arg(&input);
std::process::Command::new("ls").arg("-la");
// Command::new("sh").arg("-c").arg(format!("echo {}", input));
// Avoid invoking a shell interpreter; pass arguments directly to the executable.
