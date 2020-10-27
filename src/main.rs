use std::process::{Command,ExitStatus};
use std::env::{current_exe};
use std::io;
use std::ffi::OsString;

use thiserror::Error;

#[derive(Debug,Error)]
enum Error {
    #[error("Failed to determine filename of current executable")]
    NoFileName,
    #[error("Failed to determine folder of current executable")]
    NoParent,
    #[error("IO Error: {0}")]
    IO(#[from] io::Error)
}

type Result<T> = std::result::Result<T,Error>;

fn _main() -> Result<ExitStatus> {
    let exe = current_exe()?;
    let exename = exe.file_name().ok_or(Error::NoFileName)?;
    let parent = exe.parent().ok_or(Error::NoParent)?;
    let mut sdv_exename = OsString::new();
    sdv_exename.push("sdv.");
    sdv_exename.push(exename);
    let sdv_exe = parent.join(sdv_exename);
    let args = std::env::args_os();
    let s = Command::new(sdv_exe).args(args).status()?;
    Ok(s)
}

fn main() {
    match _main() {
        Ok(s) => {
            std::process::exit(s.code().unwrap_or(2));
        }
        Err(e) => {
            eprintln!("Error: {}",e);
            std::process::exit(1);
        }
    }
}
