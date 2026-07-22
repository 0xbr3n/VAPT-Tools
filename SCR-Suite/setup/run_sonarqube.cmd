@echo off
REM Launch a LOCAL SonarQube Community server for the optional sonarqube adapter.
REM Fully offline once the image is present (pull/save it with update_databases.ps1
REM -SonarDocker on an online machine, then: docker load -i tools\sonarqube-community.tar).
REM
REM After it starts (wait ~1 min), open http://localhost:9000  (admin/admin),
REM create a user token, then set adapters.sonarqube.enabled=true + token in config.json.
setlocal
cd /d "%~dp0.."

where docker >nul 2>nul
if errorlevel 1 (echo [!] Docker not found. Install Docker Desktop. & pause & exit /b 1)

REM load the offline image if it isn't already present
docker image inspect sonarqube:community >nul 2>nul
if errorlevel 1 (
    if exist tools\sonarqube-community.tar (
        echo Loading SonarQube image from tools\sonarqube-community.tar ...
        docker load -i tools\sonarqube-community.tar
    ) else (
        echo [!] sonarqube:community image not present and no offline tar found.
        echo     Run: powershell -File setup\update_databases.ps1 -SonarDocker   ^(online^)
        pause & exit /b 1
    )
)

echo Starting SonarQube on http://localhost:9000 (this is localhost-only, no internet needed)...
docker rm -f scr-sonarqube >nul 2>nul
docker run -d --name scr-sonarqube -p 9000:9000 sonarqube:community
echo.
echo SonarQube is starting. Give it ~60s, then browse to http://localhost:9000 (admin/admin).
echo Stop it later with:  docker rm -f scr-sonarqube
pause
