## Запуск локального сервера в докере

```bash

docker-compose up -d

```

## Компиляция под винду требует дополнительных шагов

```bash

# Установка инструментов для кросс-компиляции
brew install mingw-w64

# Установка необходимых переменных окружения
export CC=x86_64-w64-mingw32-gcc
export CXX=x86_64-w64-mingw32-g++

# Теперь можно собрать приложение
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 go build -o dist/client.exe cmd/client/*.go

```

## После компиляции под винду

```bash

# Необходимо очистить переменные окружения
unset CC
unset CXX

```

Это позволит без провлем собирать приложения под мак и линукс

Importante!

If you expiriancing the following error:
protobuf/auth/auth_grpc.pb.go:19:16: undefined: grpc.SupportPackageIsVersion9

you have to update the grpc package.

go get google.golang.org/protobuf@latest
go get google.golang.org/grpc@latest

and rebuild the proto files.

In this repo i have docker file for DB

To start DB run the following command:

```bash

docker-compose up -d

```

To stop DB run the following command:

```bash

docker-compose down

```

To start the server run the following command:

```bash

go run ./cmd/server/main.go

```

## Installing Protobuf

```sh

chmod +x proto_install.sh

./proto_install.sh

```

## Установка protoc и плагинов

1. Скачайте и установите `protoc`:
   ```sh
   curl -OL https://github.com/protocolbuffers/protobuf/releases/download/v3.19.1/protoc-3.19.1-osx-x86_64.zip
   unzip protoc-3.19.1-osx-x86_64.zip -d $HOME/protoc
   export PATH="$HOME/protoc/bin:$PATH"
   ```

To generate the gRPC code from the protobuf file, run the following command:

```bash
protoc --go_out=. --go-grpc_out=. ./protobuf/auth.proto
```
