@echo off

rd /s /q "doc"
rd /s /q "build"
call dart format --fix . || goto :error
call dart analyze --fatal-infos || goto :error
call dart doc --validate-links || goto :error
call dart test || goto :error
goto :EOF

:error
echo Failed with error #%errorlevel%.
exit /b %errorlevel%
