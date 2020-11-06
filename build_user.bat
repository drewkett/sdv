cargo build --release || exit /b 1
copy /y target\release\*.exe \\WINDEV2010EVAL\share