@echo off
REM build_bapp.bat
REM Build dist\vapt_toolkit.bapp ? a self-contained Burp Suite extension.
REM
REM What this script produces:
REM   dist\vapt_toolkit.bapp  ? JAR file loadable as a Java-type Burp extension.
REM                             Load it via Extender > Extensions > Add > Java type.
REM                             Bundles: BurpExtensionLoader.class +
REM                                      vapt_burp_extension.py   +
REM                                      jython-standalone.jar (embedded)
REM
REM Requirements:
REM   - Java 11 or later on PATH (java, javac)
REM   - Internet access on FIRST run (downloads ~3 MB of build-time JARs)
REM   - On subsequent runs the JARs are cached in .bapp-deps\
REM
REM Notes:
REM   The .bapp is a standard JAR (ZIP) renamed. Burp Suite loads it as a
REM   Java extension and the embedded Java shim (BurpExtensionLoader) uses
REM   Jython to execute vapt_burp_extension.py at runtime.
REM

setlocal EnableDelayedExpansion
cd /d "%~dp0"

set NAME=web-suite
set OUT_DIR=dist
set DEPS_DIR=.bapp-deps
set BUILD_DIR=.bapp-build
set BAPP_OUT=%OUT_DIR%\%NAME%.bapp

REM --- [0/5] Sanity checks -----------------------------------------------
echo [0/5] Checking environment...

where java  >nul 2>&1
if errorlevel 1 (
    echo [!] 'java' not found on PATH. Install JDK 11+ and try again.
    goto :err
)
where javac >nul 2>&1
if errorlevel 1 (
    echo [!] 'javac' not found on PATH. Install JDK 11+ and try again.
    exit /b 1
)

REM Locate jar.exe ? tries (1) same dir as javac, (2) JAVA_HOME\bin, (3) registry JDK path.
REM Oracle's javapath shim only contains java/javac/javaw, not jar, so the fallbacks matter.
for /f "delims=" %%i in ('where javac') do set _JAVAC_EXE=%%i
for %%i in ("%_JAVAC_EXE%") do set _JDK_BIN=%%~dpi
set JAR="%_JDK_BIN%jar.exe"

if not exist %JAR% (
    if defined JAVA_HOME (
        set JAR="%JAVA_HOME%\bin\jar.exe"
    )
)
if not exist %JAR% (
    for /f "tokens=2*" %%a in ('reg query "HKLM\SOFTWARE\JavaSoft\JDK" /v CurrentVersion 2^>nul') do set _JDK_VER=%%b
    if defined _JDK_VER (
        for /f "tokens=2*" %%a in ('reg query "HKLM\SOFTWARE\JavaSoft\JDK\!_JDK_VER!" /v JavaHome 2^>nul') do set _JDK_HOME=%%b
        if defined _JDK_HOME set JAR="!_JDK_HOME!\bin\jar.exe"
    )
)
if not exist %JAR% (
    echo [!] jar.exe not found. Set JAVA_HOME to your JDK directory and retry.
    goto :err
)

for /f "tokens=3" %%v in ('java -version 2^>^&1 ^| findstr /i "version"') do (
    set JAVA_VER=%%v
)
echo     Java: %JAVA_VER%
echo     jar : %JAR%

REM --- [1/5] Prepare directories -----------------------------------------
echo [1/5] Preparing build directories...
if not exist "%DEPS_DIR%" mkdir "%DEPS_DIR%"
if not exist "%OUT_DIR%"  mkdir "%OUT_DIR%"
if exist "%BUILD_DIR%"    rmdir /s /q "%BUILD_DIR%"
mkdir "%BUILD_DIR%"
mkdir "%BUILD_DIR%\META-INF"

REM --- [2/5] Download dependencies (cached) ------------------------------
echo [2/5] Fetching dependencies...

REM Burp Suite Extender API JAR (legacy IBurpExtender interface)
set BURP_JAR=%DEPS_DIR%\burp-extender-api-2.3.jar
if not exist "%BURP_JAR%" (
    echo     Downloading burp-extender-api-2.3.jar...
    powershell -NoProfile -Command "Invoke-WebRequest -Uri 'https://repo1.maven.org/maven2/net/portswigger/burp/extender/burp-extender-api/2.3/burp-extender-api-2.3.jar' -OutFile '%BURP_JAR%' -UseBasicParsing"
    if not exist "%BURP_JAR%" (
        echo [!] Failed to download burp-extender-api. Check internet connection.
        echo     Alternatively, copy the burp extender API jar manually to:
        echo       %BURP_JAR%
        goto :err
    )
    echo     Downloaded: %BURP_JAR%
) else (
    echo     Cached: %BURP_JAR%
)

REM Jython standalone JAR (Python 2.7 runtime ? embedded inside the .bapp)
set JYTHON_VER=2.7.3
set JYTHON_JAR=%DEPS_DIR%\jython-standalone-%JYTHON_VER%.jar
if not exist "%JYTHON_JAR%" (
    echo     Downloading jython-standalone-%JYTHON_VER%.jar ^(~10 MB^)...
    powershell -NoProfile -Command "Invoke-WebRequest -Uri 'https://repo1.maven.org/maven2/org/python/jython-standalone/%JYTHON_VER%/jython-standalone-%JYTHON_VER%.jar' -OutFile '%JYTHON_JAR%' -UseBasicParsing"
    if not exist "%JYTHON_JAR%" (
        echo [!] Failed to download Jython. Check internet connection.
        goto :err
    )
    echo     Downloaded: %JYTHON_JAR%
) else (
    echo     Cached: %JYTHON_JAR%
)

REM --- [3/5] Compile BurpExtensionLoader.java ----------------------------
echo [3/5] Compiling BurpExtensionLoader.java...

javac --release 11 ^
  -classpath "%BURP_JAR%;%JYTHON_JAR%" ^
  -d "%BUILD_DIR%" ^
  BurpExtensionLoader.java

if errorlevel 1 (
    echo [!] Compilation failed.
    goto :err
)
echo     Compiled OK.

REM --- [4/5] Copy resources into the build tree --------------------------
echo [4/5] Assembling package contents...

REM Embed the Python extension source. The file is too large for Jython to
REM compile into a single Java class (64KB/constant-pool limits), so split it
REM into vapt_partN.py chunks at safe class boundaries. The loader execs them
REM in order into one interpreter namespace.
echo     Splitting Python source into parts...
powershell -NoProfile -ExecutionPolicy Bypass -File "_split_parts.ps1" -Src "vapt_burp_extension.py" -OutDir "%BUILD_DIR%"
if errorlevel 1 (
    echo [!] Source split failed. Falling back to single-file embed.
    copy /y "vapt_burp_extension.py" "%BUILD_DIR%\vapt_burp_extension.py" >nul
)

REM Explode Jython into the build tree so it's available on the classpath
REM inside the final JAR (no nested-JAR classloader tricks needed).
echo     Extracting Jython classes into build tree (this takes ~10 seconds)...
cd "%BUILD_DIR%"
%JAR% xf "..\%JYTHON_JAR%"
if errorlevel 1 (
    cd ..
    echo [!] Failed to extract Jython JAR.
    goto :err
)
cd ..

REM Write MANIFEST.MF
(
    echo Manifest-Version: 1.0
    echo Main-Class: BurpExtensionLoader
    echo Created-By: build_bapp.bat
    echo Extension-Name: Web VAPT Toolkit
    echo.
) > "%BUILD_DIR%\META-INF\MANIFEST.MF"

REM --- [5/5] Package as .bapp (JAR) --------------------------------------
echo [5/5] Packaging %BAPP_OUT%...

%JAR% cfm "%BAPP_OUT%" "%BUILD_DIR%\META-INF\MANIFEST.MF" ^
  -C "%BUILD_DIR%" .

if errorlevel 1 (
    echo [!] JAR packaging failed.
    goto :err
)

REM Burp 2026's "Add extension (Java)" file chooser only lists *.jar (older Burp
REM also accepted *.bapp). The archive is identical, so emit a .jar copy too.
set JAR_OUT=%OUT_DIR%\%NAME%.jar
copy /y "%BAPP_OUT%" "%JAR_OUT%" >nul

echo.
echo ============================================================
echo  Build complete!
echo ============================================================
echo.
echo  Output : %CD%\%BAPP_OUT%
echo           %CD%\%JAR_OUT%   (use THIS on Burp 2026+)
echo.
echo  Load in Burp Suite:
echo    Extensions ^> Add ^> Extension type: Java
echo    Extension file : %CD%\%JAR_OUT%      (Burp 2026+ only lists .jar)
echo                  or %CD%\%BAPP_OUT%      (older Burp accepts .bapp)
echo.
echo  OR load the Python source directly (requires Jython):
echo    Extender ^> Options ^> Python Environment: jython-standalone.jar
echo    Extender ^> Extensions ^> Add ^> Python type ^> vapt_burp_extension.py
echo.
goto :end

:err
echo [!] Build failed. See errors above.
exit /b 1

:end
endlocal
