BINARY := dnsserver
BIN_DIR := bin
CMD_DIR := ./cmd/dnsserver

.PHONY: build run clean test

build:
	go build -o $(BIN_DIR)/$(BINARY) $(CMD_DIR)

run: build
	./$(BIN_DIR)/$(BINARY)

test:
	go test ./...

clean:
	rm -rf $(BIN_DIR)
