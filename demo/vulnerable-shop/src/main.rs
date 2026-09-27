use std::process::Command;

pub fn execute_report(cmd_str: &str) {
    Command::new("sh").arg("-c").arg(cmd_str);
}
