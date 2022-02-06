@REM disable secure boot if needed
@REM bcdedit -set testsigning on
net stop sdvfilter
call build_kernel.bat || exit /b 1
rundll32.exe advpack.dll,LaunchINFSectionEx %~dp0x64\Release\sdvfilter.inf,,,4 || exit /b 1
net start sdvfilter || exit /b 1
cargo run --release --bin sdv -- test-io.exe
