msbuild /p:Configuration=Release || exit /b 1
copy /y x64\Release\FsFilter1.* \\WINDEV2010EVAL\share