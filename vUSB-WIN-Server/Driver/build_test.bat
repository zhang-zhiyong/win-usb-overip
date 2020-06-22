set OCD=%CD%
set TYPE=fre

IF "%BASEDIR%"=="" (
set BASEDIR=D:\WinDDK\7600.16385.1
CALL C:\WinDDK\7600.16385.1\bin\setenv.bat C:\WinDDK\7600.16385.1 %TYPE%     WLH
cd /d %OCD%
)

cmd /C "set DDKBUILDENV=&& %BASEDIR%\bin\setenv.bat %BASEDIR% %TYPE%     WLH && cd /d %OCD% && build"
cmd /C "set DDKBUILDENV=&& %BASEDIR%\bin\setenv.bat %BASEDIR% %TYPE% x64 WLH && cd /d %OCD% && build"

mkdir UsbRedir
copy VanXumUsbRedir.inf UsbRedir
copy obj%TYPE%_wlh_x86\i386\VanXumUsbRedir.sys UsbRedir\VanXumUsbRedir_x86.sys
copy obj%TYPE%_wlh_amd64\amd64\VanXumUsbRedir.sys UsbRedir\VanXumUsbRedir_x64.sys


