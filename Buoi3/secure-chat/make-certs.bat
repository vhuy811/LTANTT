@echo off
setlocal enabledelayedexpansion
:: Di chuyen vao thu muc chua file nay
cd /d %~dp0
:: Tao cac thu muc con trong certs/
mkdir certs\ca
mkdir certs\server
mkdir certs\client
:: CA tu ky (RSA 2048, SHA-256, han 3650 ngay)
openssl genrsa -out certs\ca\ca.key 2048
openssl req -x509 -new -nodes -key certs\ca\ca.key -sha256 -days 3650 -out certs\ca\ca.crt -config openssl.cnf -extensions v3_ca
:: Server (CN=localhost), CA ky
openssl genrsa -out certs\server\server.key 2048
openssl req -new -key certs\server\server.key -out certs\server\server.csr -subj "/C=VN/ST=HN/L=HN/O=MyOrg/OU=IT Dept/CN=localhost"
openssl x509 -req -in certs\server\server.csr -CA certs\ca\ca.crt -CAkey certs\ca\ca.key -CAcreateserial -out certs\server\server.crt -days 365 -sha256
:: Client (CN=client), CA ky
openssl genrsa -out certs\client\client.key 2048
openssl req -new -key certs\client\client.key -out certs\client\client.csr -subj "/C=VN/ST=HN/L=HN/O=MyOrg/OU=IT Dept/CN=client"
openssl x509 -req -in certs\client\client.csr -CA certs\ca\ca.crt -CAkey certs\ca\ca.key -CAcreateserial -out certs\client\client.crt -days 365 -sha256
:: Doi ten file serial de tranh de
move certs\ca\ca.srl certs\ca\ca.srl.bak >nul 2>&1
echo.
echo ===============================
echo Cac chung chi da tao xong!
echo - CA: certs\ca\
echo - Server: certs\server\
echo - Client: certs\client\
echo ===============================
pause
