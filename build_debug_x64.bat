cd /d "%~dp0"
setlocal
set msbuild2017=C:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\MSBuild\15.0\bin\msbuild.exe
set msbuild2019=C:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\MSBuild\Current\bin\msbuild.exe
"%msbuild2019%" -t:restore
"%msbuild2019%" ExchangeFilter.sln /nologo /v:minimal /p:Configuration=Debug /p:Platform=x64 /p:AppendTargetFrameworkToOutputPath=false /target:Clean;Rebuild /nodeReuse:false /noWarn:1138;NETSDK1138;1701;NETSDK1701;NU1701;1702;NU1702;NETSDK1702
if errorlevel 1 pause
endlocal
