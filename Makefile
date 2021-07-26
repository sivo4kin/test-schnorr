SRC=./src
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get

PHONY: deps

all: deps clean test

go_test:
	$(GOTEST) -v $(SRC)...

test: go_test hh_test

yarn:
	cd eth-contracts;yarn;
go:
	cd $SRC;go mod tidy;go mod download;$(GOGET) "github.com/ethereum/go-ethereum";$(GOGET) "github.com/pkg/errors@v0.9.1"

deps: yarn go

hh_test:
	cd eth-contracts && npx hardhat test
clean:
	rm -rf test_data/*_test.js

npm:
	@if [ -d truffle/node_modules ]; then \
  			echo "installed"; \
  			else \
  			cd truffle;npm i;fi
