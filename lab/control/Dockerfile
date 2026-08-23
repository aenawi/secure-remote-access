# The control server. One static binary with the UI compiled into it, in an
# image with no shell, no package manager and nothing else to run — which is
# what you want from the one container in this stack holding the Docker socket.
FROM golang:1.26-alpine AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /control .

FROM gcr.io/distroless/static-debian12:latest
COPY --from=build /control /control
EXPOSE 8099
ENTRYPOINT ["/control"]
