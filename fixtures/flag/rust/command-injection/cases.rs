Command::new("sh").arg("-c").arg(format!("echo {}", input));
Command::new("bash").args(["-c", &user_cmd]);
Command::new("sh").arg("-c").arg(cmd_str);
process::Command::new("/bin/sh").arg("-c").arg(&format!("cat {}", file));
std::process::Command::new("sh").arg("-c").arg(&user_input);
Command::new("/usr/bin/bash").arg("-c").arg(format!("rm -rf {}", dir));
