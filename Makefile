BINARY_NAME=lego-scp-solver
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS=-ldflags "-X main.version=${VERSION}"

.PHONY: all build clean test

all: build

build:
	go build -buildvcs=false ${LDFLAGS} -o ${BINARY_NAME} .

clean:
	go clean
	rm -f ${BINARY_NAME}

test:
	go test -v ./...

install:
	go install -buildvcs=false ${LDFLAGS}

# Cross-compilation targets
build-linux:
	GOOS=linux GOARCH=amd64 go build -buildvcs=false ${LDFLAGS} -o ${BINARY_NAME}-linux-amd64 .
	GOOS=linux GOARCH=arm64 go build -buildvcs=false ${LDFLAGS} -o ${BINARY_NAME}-linux-arm64 .
	GOOS=linux GOARCH=arm GOARM=7 go build -buildvcs=false ${LDFLAGS} -o ${BINARY_NAME}-linux-armv7 .

build-mac:
	GOOS=darwin GOARCH=amd64 go build -buildvcs=false ${LDFLAGS} -o ${BINARY_NAME}-darwin-amd64 .
	GOOS=darwin GOARCH=arm64 go build -buildvcs=false ${LDFLAGS} -o ${BINARY_NAME}-darwin-arm64 .

build-windows:
	GOOS=windows GOARCH=amd64 go build -buildvcs=false ${LDFLAGS} -o ${BINARY_NAME}-windows-amd64.exe .

build-all: build-linux build-mac build-windows