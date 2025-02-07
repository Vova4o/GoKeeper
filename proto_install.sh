# Установите protoc (если еще не установлен)
brew install protobuf

# Установите плагины для Go
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Добавьте Go bin в ваш PATH (добавьте эту строку в ваш .bashrc, .zshrc или другой файл конфигурации оболочки)
export PATH="$PATH:$(go env GOPATH)/bin"