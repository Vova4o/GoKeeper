To generate the gRPC code from the protobuf file, run the following command:

```bash
protoc --go_out=. --go-grpc_out=. ./protobuf/auth.proto
```

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