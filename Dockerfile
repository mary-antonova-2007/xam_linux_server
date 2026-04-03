FROM golang:1.25 AS build
WORKDIR /src

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o /out/linux_server ./cmd/server

FROM gcr.io/distroless/base-debian12
WORKDIR /app
COPY --from=build /out/linux_server /app/linux_server
EXPOSE 8080
ENTRYPOINT ["/app/linux_server"]
