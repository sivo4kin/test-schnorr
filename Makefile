GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get

all: deps clean test

go_test:
	$(GOTEST) -v ./signatures/...

test: go_test hh_test

deps: npm
	go mod tidy
	go mod download
	$(GOGET) "github.com/ethereum/go-ethereum"
	$(GOGET) "github.com/pkg/errors@v0.9.1"

hh_test:
	cd eth-contracts && npx hardhat test
clean:
	rm -rf test_data/*_test.js

npm:
	@if [ -d truffle/node_modules ]; then \
  			echo "installed"; \
  			else \
  			cd truffle;npm i;fi
