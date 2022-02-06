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

Legend
```
I -> Input File (ie file that was read from)
O -> Output File (ie file that was written to)
U -> Updated File (ie file that was read from and written to)
```

Currently temporary files (ie files that are created and then deleted before the process ends) are excluded.


## How it works

The kernel driver is a mini-filter driver which separately tracks process creation/deletion, image load/unload and I/O operations. For each event, it sends a message to the user space process `sdv.exe` using a filter communication port. The kernel driver is intentionally "dumb" and doesn't do anything beyond just sending the messages to the user space process for all events. This is to keep that code as simple as possible since it runs in the kernel. 

The user space process `sdv.exe` continually receives these messages and then maps the three types of operations (process, image, I/O) into a coherent view of the data which incoporates the process id, the file names that are read and written and the image name (ie the process name) of the process. Since this is just a demo utility, it just prints out the information for the process names of interest which are passed to the `sdv.exe` as arguments.
