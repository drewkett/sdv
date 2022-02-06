use std::{fs, io};

fn main() -> io::Result<()> {
    let temp_files = ["target/temp.txt"];
    for p in temp_files {
        fs::write(p, "hi")?;
    }
    let input_files = ["Cargo.toml"];
    for p in input_files {
        let _ = fs::read(p)?;
    }
    let output_files = ["target/out1.txt", "target/out2.txt"];
    for p in output_files {
        fs::write(p, "hi")?;
    }
    for p in temp_files {
        fs::remove_file(p)?;
    }
    Ok(())
}
