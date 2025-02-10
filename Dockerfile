FROM golang:1.22-alpine

WORKDIR /app

# Установка необходимых зависимостей
RUN apk add --no-cache gcc musl-dev openssl postgresql-client

# Копирование файлов проекта
COPY go.mod go.sum ./
RUN go mod download

# Копирование исходного кода и скриптов
COPY . .

# Делаем скрипт генерации сертификатов исполняемым
RUN chmod +x generate_cert.sh

# Сборка приложения
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./cmd/server/*.go

# Порты
EXPOSE 50051
EXPOSE 8080

# Запуск приложения
CMD ["./server"]