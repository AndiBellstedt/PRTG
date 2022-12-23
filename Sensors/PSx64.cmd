@echo off
setlocal enabledelayedexpansion

SET AllParameter=%*
SET FirstParameter=%1
SET replace=
CALL SET scriptParameter=%%AllParameter:!FirstParameter!=!replace!%%

"%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy RemoteSigned -NoLogo -NonInteractive -NoProfile -File "C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXEXML\%FirstParameter%"%scriptParameter%
rem "%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe" -ExecutionPolicy RemoteSigned -NoLogo -NonInteractive -NoProfile -Command "& { .'C:\Program Files (x86)\PRTG Network Monitor\Custom Sensors\EXEXML\%FirstParameter%'%scriptParameter% }"

