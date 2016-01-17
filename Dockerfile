FROM golang:latest

RUN go get github.com/dimorinny/echo-jwt/... && go install github.com/dimorinny/echo-jwt/sample/

# Run the outyet command by default when the container starts.
ENTRYPOINT /go/bin/sample

# Document that the service listens on port 8080.
EXPOSE 1323