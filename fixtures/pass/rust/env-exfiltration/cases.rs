// False positive cases for rust/env-exfiltration
use std::env;

fn pass_cases() {
    // Case 1: targeted single env var fetch
    let _port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());

    // Case 2: targeted single env var with std::env
    let _db = std::env::var("DATABASE_URL");

    // Case 3: setting an env var
    env::set_var("APP_ENV", "production");

    // Case 4: reading command-line args
    let _args: Vec<String> = env::args().collect();

    // Case 5: custom struct method called vars()
    struct Config;
    impl Config {
        fn vars(&self) -> Vec<String> { vec![] }
    }
    let cfg = Config;
    let _ = cfg.vars();

    // Case 6: checking if var_os is set
    let _val = env::var_os("HOME");
}
