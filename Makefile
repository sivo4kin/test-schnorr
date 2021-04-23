GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get

all: deps clean test

go_test:
	$(GOTEST) -v ./...

test: go_test truffle_test

deps: npm
	$(GOGET) "github.com/ethereum/go-ethereum"
	$(GOGET) "github.com/pkg/errors@v0.9.1"

truffle_test:
	cd truffle && npx truffle test
clean:
	rm -rf files/*_test.js

npm:
	@if [ -d truffle/node_modules ]; then \
  			echo "installed"; \
  			else \
  			cd truffle;npm i;fi
