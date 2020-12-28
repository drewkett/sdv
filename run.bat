@REM disable secure boot if needed
@REM bcdedit -set testsigning on
ssh user@WINDEV2010EVAL "net stop fsfilter1"
copy /y x64\Release\FsFilter1.* \\WINDEV2010EVAL\share
ssh user@WINDEV2010EVAL "rundll32.exe advpack.dll,LaunchINFSectionEx C:\share\FsFilter1.inf,,,4" || exit /b 1
ssh user@WINDEV2010EVAL "net start fsfilter1" || exit /b 1
copy /y target\release\*.exe \\WINDEV2010EVAL\share
ssh user@WINDEV2010EVAL "C:\share\sdv-user.exe" || exit /b 1
