use std::path::{Path, PathBuf};

fn flag_cases(user_file: &str, input: &str, filename: &str, name: &str, dir: &str, file: &str, id: &str) {
    // 1. Path::new with &format!
    let _p1 = Path::new(&format!("/uploads/{}", user_file));

    // 2. PathBuf::from with format!
    let _p2 = PathBuf::from(format!("data/{}", input));

    // 3. path.join with format!
    let base = Path::new("/var/app");
    let _p3 = base.join(format!("{}.txt", filename));

    // 4. Path::new with &format! directory structure
    let _p4 = Path::new(&format!("{}/file", name));

    // 5. PathBuf::from with &format! and %s
    let _p5 = PathBuf::from(&format!("/var/data/%s", id));

    // 6. path.join with &format!
    let _p6 = base.join(&format!("{}/{}", dir, file));
}
