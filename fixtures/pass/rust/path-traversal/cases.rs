use std::path::{Path, PathBuf};

fn pass_cases(user_file: &str, input: &str) {
    // 1. Static string Path::new
    let _p1 = Path::new("/etc/hosts");

    // 2. Static string PathBuf::from
    let _p2 = PathBuf::from("config.json");

    // 3. Static path.join
    let base = Path::new("/var/app");
    let _p3 = base.join("subfolder").join("file.txt");

    // 4. path.canonicalize for validation
    let _p4 = base.canonicalize();

    // 5. Commented out format! path construction
    // let _p5 = Path::new(&format!("/uploads/{}", user_file));

    // 6. format! for non-path string logging or messages
    let _msg = format!("User input received: {}", input);

    // 7. format! inside non-path functions
    println!("{}", format!("processing request for {}", input));

    // 8. PathBuf::from with sanitized variable (no format!)
    let sanitized = "safe_filename.txt";
    let _p6 = PathBuf::from(sanitized);

    // 9. path.join with sanitized variable (no format!)
    let _p7 = base.join(sanitized);
}
