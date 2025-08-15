# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

This is a learning project to implement OAuth 2.1 in Go. The goal is to create a multi-component system to understand OAuth message exchanges for implementing OAuth in an MCP server.

## Project architecture

The planned system consists of:

1. **Client application** - requests resources from the provider
2. **Resource provider** - serves resources only to authorized clients
3. **Authorization server** - handles authentication (may be separate or integrated with resource provider)

All components should log and display OAuth messages in formatted text to demonstrate the authentication flow.

## Development requirements

- Use Go standard library whenever possible
- Use Chi library for web services
- Store sample accounts in source code or JSON files (no database required)
- Include detailed step-by-step documentation of the OAuth flow
- Display all OAuth message exchanges clearly marked between components

## Commands

### Build and run
```bash
go mod tidy          # Download dependencies
go build ./...       # Build all components
go run .             # Run main application
```

### Testing
```bash
go test ./...        # Run all tests
go test -v ./...     # Run tests with verbose output
```

### Development
```bash
go fmt ./...         # Format code
go vet ./...         # Static analysis
```

## Documentation

- **README.md**: Comprehensive project documentation with step-by-step OAuth 2.1 flow walkthrough
- **docs/README.md**: Additional technical documentation
- **Makefile**: Build and run commands with demo instructions

## Key considerations

- Password encryption should be included if it doesn't significantly increase complexity
- Focus on educational value and clear demonstration of OAuth flows
- Prioritize readability and understanding over production-level security