use std::fs::{File, OpenOptions};

fn pass_cases() -> std::io::Result<()> {
    let id = "test-uuid";

    // Near-miss 1: tempfile crate NamedTempFile
    let named_file = tempfile::NamedTempFile::new()?;

    // Near-miss 2: tempfile crate tempdir
    let dir = tempfile::tempdir()?;

    // Near-miss 3: Commented out insecure temporary file creation
    // let f = File::create("/tmp/scratch.txt")?;

    // Near-miss 4: Relative path creation
    let rel_file = File::create("relative_path.txt")?;

    // Near-miss 5: format! with local relative path
    let local_path = format!("./data/{}.tmp", id);

    // Near-miss 6: tempfile Builder
    let custom_tmp = tempfile::Builder::new().prefix("cache").tempfile()?;

    // Near-miss 7: OpenOptions on relative path
    let local_log = OpenOptions::new().write(true).open("local.log")?;

    Ok(())
}
