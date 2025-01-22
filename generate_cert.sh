#!/bin/bash

# Генерация приватного ключа
openssl genpkey -algorithm RSA -out server.key -pkeyopt rsa_keygen_bits:2048

# Создание конфигурационного файла для SANs
cat > san.cnf <<EOL
[req]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
CN = localhost

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
EOL

# Генерация запроса на сертификат (CSR) с использованием SANs
openssl req -new -key server.key -out server.csr -config san.cnf

# Генерация самоподписанного сертификата с использованием SANs
openssl x509 -req -in server.csr -signkey server.key -out server.crt -days 365 -extfile san.cnf -extensions req_ext

# Удаление временных файлов
rm server.csr san.cnf