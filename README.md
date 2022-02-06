This project is a demo Windows kernel mini-filter written in C that sends messages regarding process and file usage to a user space process written in Rust.

## Prerequisites

You need to install visual studio build tools with Windows SDK and the Enterprise WDK for kernel development. You also need to enable testsigning `bcdedit -set testsigning on` if you don't have certificate from msft for driver development. (This might require turning off secure boot as well). You need a rust installation as well 

## To Run

To run it, you can use `run.bat` which will attempt to build the driver `sdvfilter` using `build_driver.bat`, install the driver, start the driver and then build and run the user space watching program `sdv.exe`. The arguments to `sdv.exe` are executable names who's process execution you want tracked. `run.bat` currently just tracks `test-io.exe` which is a sample executable inside `src/bin`, which can be run with `cargo run --release --bin test-io`. With `sdv` running, the sample output you'll see when you run `test-io.exe` will look like this

```
Process 15396 finished (ParentID 2116) \\?\C:\Users\Andrew\Dev\sdv\target\release\test-io.exe
I \\?\C:\Users\Andrew\Dev\sdv\Cargo.toml
O \\?\C:\Users\Andrew\Dev\sdv\target\out1.txt
O \\?\C:\Users\Andrew\Dev\sdv\target\out2.txt
```
