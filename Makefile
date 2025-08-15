.PHONY: help build run-auth run-resource run-client run-all clean test fmt vet

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build all applications
	@echo "Building OAuth 2.1 applications..."
	@go build -o bin/auth-server cmd/auth-server/main.go
	@go build -o bin/resource-server cmd/resource-server/main.go
	@go build -o bin/client cmd/client/main.go
	@echo "Build complete. Binaries in bin/ directory."

run-auth: ## Run authorization server (port 8081)
	@echo "Starting Authorization Server on port 8081..."
	@go run cmd/auth-server/main.go

run-resource: ## Run resource server (port 8082)
	@echo "Starting Resource Server on port 8082..."
	@go run cmd/resource-server/main.go

run-client: ## Run client application (port 8080)
	@echo "Starting Client Application on port 8080..."
	@go run cmd/client/main.go

run-all: ## Run all servers in background (requires terminal multiplexer)
	@echo "Starting all OAuth 2.1 components..."
	@echo "Authorization Server: http://localhost:8081"
	@echo "Resource Server: http://localhost:8082"
	@echo "Client Application: http://localhost:8080"
	@echo ""
	@echo "Run in separate terminals:"
	@echo "  make run-auth"
	@echo "  make run-resource"  
	@echo "  make run-client"

test: ## Run tests
	@go test ./...

fmt: ## Format code
	@go fmt ./...

vet: ## Run go vet
	@go vet ./...

clean: ## Clean build artifacts
	@rm -rf bin/
	@echo "Clean complete."

deps: ## Download dependencies
	@go mod tidy
	@go mod download

check: fmt vet test ## Run all checks (format, vet, test)

demo: ## Show demo instructions
	@echo "OAuth 2.1 Demo Instructions:"
	@echo "1. Start all three servers in separate terminals:"
	@echo "   Terminal 1: make run-auth"
	@echo "   Terminal 2: make run-resource"
	@echo "   Terminal 3: make run-client"
	@echo ""
	@echo "2. Open browser to: http://localhost:8080"
	@echo ""
	@echo "3. Demo accounts:"
	@echo "   alice / password123"
	@echo "   bob / secret456"
	@echo "   carol / mypass789"
	@echo ""
	@echo "4. Follow the OAuth flow in the browser"
	@echo "5. Watch the colored message logs in each terminal"