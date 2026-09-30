use std::fs::{File, OpenOptions};

fn flag_cases() -> std::io::Result<()> {
    let user_id = 1001;
    let id = "test-uuid";

    // Case 1: File::create in /tmp
    let f = File::create("/tmp/scratch.txt")?;

    // Case 2: OpenOptions in /tmp
    let mut file = OpenOptions::new().write(true).open("/tmp/output.log")?;

    // Case 3: format! path in /tmp
    let path = format!("/tmp/user_{}.tmp", user_id);

    // Case 4: format! path in /var/tmp
    let p = format!("/var/tmp/upload_{}.bin", id);

    // Case 5: File::create in /var/tmp
    let tmp = File::create("/var/tmp/temp.dat")?;

    Ok(())
}
