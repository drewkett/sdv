@REM call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
@REM C:\EWDK contains the Enterprise WDK iso extracted 
call "C:\EWDK\BuildEnv\SetupBuildEnv.cmd"
msbuild /p:Configuration=Release || exit /b 1