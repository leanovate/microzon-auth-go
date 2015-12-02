DEPS = $(shell go list -f '{{range .TestImports}}{{.}} {{end}}' ./...)
PACKAGES = $(shell go list ./...)
VETARGS?=-asmdecl -atomic -bool -buildtags -copylocks -methods \
         -nilfunc -printf -rangeloops -shift -structtags -unsafeptr
DEPPATH = $(firstword $(subst :, , $(GOPATH)))
VERSION = $(shell date -u +.%Y%m%d.%H%M%S)

all: export GOPATH=${PWD}/Godeps/_workspace:${PWD}/../../../..
all: format
	@mkdir -p bin/
	@echo "--> Running go build"
	@go build -ldflags "-X github.com/leanovate/microzon-auth-go/config.versionMinor=${VERSION}" -v -o bin/microzon-auth github.com/leanovate/microzon-auth-go

deps:
	@echo "--> Installing build dependencies"
	@go get -d -v ./... $(DEPS)

updatedeps: deps
	@echo "--> Updating build dependencies"
	@go get -d -f -u ./... $(DEPS)

test: export GOPATH=${PWD}/Godeps/_workspace:${PWD}/../../../..
test: deps
	@go test -v ./...
	@$(MAKE) vet

format: export GOPATH=${PWD}/Godeps/_workspace:${PWD}/../../../..
format: deps
	@echo "--> Running go fmt"
	@go fmt ./...

goconvey:
	@go build -v -o bin/goconvey github.com/smartystreets/goconvey
	@bin/goconvey

docker: export GOPATH=${PWD}/Godeps/_workspace:${PWD}/../../../..
docker: export GOOS=linux
docker: export GOARCH=amd64
docker: export CGO_ENABLED=0
docker:
	@mkdir -p bin/
	@echo "--> Running go build (linux, amd64)"
	@go build -ldflags "-X github.com/leanovate/microzon-auth-go/config.versionMinor=${VERSION}" -v -o bin/microzon-auth github.com/leanovate/microzon-auth-go
	@docker-compose build microzon-auth

vet: export GOPATH=${PWD}/Godeps/_workspace:${PWD}/../../../..
vet:
	@go tool vet 2>/dev/null ; if [ $$? -eq 3 ]; then \
		go get golang.org/x/tools/cmd/vet; \
	fi
	@echo "--> Running go tool vet $(VETARGS)"
	@find . -name "*.go" | grep -v "./Godeps/" | xargs go tool vet $(VETARGS); if [ $$? -eq 1 ]; then \
		echo ""; \
		echo "Vet found suspicious constructs. Please check the reported constructs"; \
		echo "and fix them if necessary before submitting the code for reviewal."; \
	fi

godepssave:
	@echo "--> Godeps save"
	@go build -v -o bin/godep github.com/tools/godep
	@bin/godep save

genmocks:
	@echo "--> Generate mocks"
	@go build -v -o bin/mockgen github.com/golang/mock/mockgen
	bin/mockgen -source=./logging/logger.go -destination=./logging/logger_mock.go -package logging
	bin/mockgen -source=./store/store.go -destination=./store/store_mock.go -package store
