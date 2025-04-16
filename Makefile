# Makefile for building a Go binary

# Variables
APP_NAME := jwks_demo
SRC_DIR := .
BUILD_DIR := bin
GO := go

# Default target
.PHONY: all
all: build

# Build the Go binary (static build)
.PHONY: build
build:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 $(GO) build -tags netgo -o $(BUILD_DIR)/$(APP_NAME) $(SRC_DIR)

# Clean up build artifacts
.PHONY: clean
clean:
	@rm -rf $(BUILD_DIR)

# Run the application
.PHONY: run
run: build
	./$(BUILD_DIR)/$(APP_NAME)

# Format the code
.PHONY: fmt
fmt:
	$(GO) fmt ./...

# Run tests
.PHONY: test
test:
	$(GO) test -v ./...

# Lint the code (using staticcheck)
.PHONY: lint
lint:
	staticcheck -v ./...
