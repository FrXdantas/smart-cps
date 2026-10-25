@echo off
REM subir.bat - sobe o SMART ESBMC / JBMC no Windows (Docker Desktop). Sem internet.
REM   subir.bat           sobe (carrega a imagem do .tar.gz na 1a vez)
REM   subir.bat parar     para (os dados ficam guardados)
REM   subir.bat logs      log ao vivo (Ctrl+C sai)
setlocal
cd /d "%~dp0"
set IMAGEM=smartcps:2.4-cps
set NOME=smartcps
set PORTA=8100

docker info >nul 2>&1 || (echo ERRO: abra o Docker Desktop e espere ficar verde. & pause & exit /b 1)

if /i "%1"=="parar" ( docker stop %NOME% & echo Parado. Dados preservados. & exit /b 0 )
if /i "%1"=="logs"  ( docker logs -f --tail 100 %NOME% & exit /b 0 )

docker image inspect %IMAGEM% >nul 2>&1
if errorlevel 1 (
  if not exist smartcps-imagem.tar.gz ( echo ERRO: falta o arquivo smartcps-imagem.tar.gz nesta pasta. & pause & exit /b 1 )
  echo Carregando a imagem ^(so na 1a vez, 1-2 min^)...
  docker load -i smartcps-imagem.tar.gz || ( pause & exit /b 1 )
)

docker rm -f %NOME% >nul 2>&1
set ENVF=
if exist smartcps.env set ENVF=--env-file smartcps.env
docker run -d --name %NOME% --restart unless-stopped -p %PORTA%:8000 -e HOST_PORT=%PORTA% -v smartcps-dados:/app/data %ENVF% %IMAGEM% || ( pause & exit /b 1 )

echo Subindo... aguarde uns 10 segundos.
timeout /t 10 /nobreak >nul
docker logs %NOME% 2>&1 | findstr /c:"admin criado"
echo.
echo No ar: http://localhost:%PORTA%
start http://localhost:%PORTA%
endlocal
