GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get

all: deps clean test
test:
	$(GOTEST) -v ./...
	cd truffle && npx truffle test
deps:
	$(GOGET) "github.com/ethereum/go-ethereum"
	$(GOGET) "github.com/pkg/errors@v0.9.1"
	cd truffle && npm i
truffle_test:
	cd truffle && npx truffle test
clean:
	rm -rf files/*_test.js