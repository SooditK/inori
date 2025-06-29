FROM golang:1.22-alpine

WORKDIR /app
COPY . .
RUN go build -o secrets-server

EXPOSE 8080
CMD [\"./secrets-server\"]