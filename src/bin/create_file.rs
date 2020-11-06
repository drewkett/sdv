use std::fs;
use std::io;

fn main() -> io::Result<()> {
    let p = "blah.txt";
    {
        use io::Write;
        let mut f = fs::File::create(p)?;
        write!(f, "Hi")?;
    }
    let p2 = "blah2.txt";
    {
        use io::Write;
        let mut f = fs::File::create(p2)?;
        write!(f, "Hi")?;
    }
    fs::remove_file(p)
}
