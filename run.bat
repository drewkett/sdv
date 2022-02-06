@REM disable secure boot if needed
@REM bcdedit -set testsigning on
net stop fsfilter1
rundll32.exe advpack.dll,LaunchINFSectionEx %~dp0x64\Release\FsFilter1.inf,,,4 || exit /b 1
net start fsfilter1 || exit /b 1
target\release\sdv-user.exe || exit /b 1
