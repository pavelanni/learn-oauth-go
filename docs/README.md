# OAuth 2.1 Learning Project

A complete implementation of OAuth 2.1 authorization code flow with PKCE in Go, designed for educational purposes.

## Project overview

This project demonstrates the OAuth 2.1 authorization code flow through three interconnected applications:

- **Authorization Server** (port 8081) - Handles user authentication and issues tokens
- **Resource Server** (port 8082) - Protects and serves resources to authorized clients  
- **Client Application** (port 8080) - Initiates OAuth flow and accesses protected resources

## Quick start

1. **Install dependencies:**
   ```bash
   go mod tidy
   ```

2. **Start all three servers** (in separate terminals):
   ```bash
   # Terminal 1: Authorization Server
   go run cmd/auth-server/main.go
   
   # Terminal 2: Resource Server  
   go run cmd/resource-server/main.go
   
   # Terminal 3: Client Application
   go run cmd/client/main.go
   ```

3. **Begin OAuth flow:**
   - Open browser to http://localhost:8080
   - Click "Start OAuth Flow"
   - Login with demo credentials (alice/password123, bob/secret456, or carol/mypass789)
   - Complete the flow to access protected resources

## OAuth 2.1 flow demonstration

### Step 1: Authorization request
The client generates a PKCE challenge and redirects the user to the authorization server with:
- `client_id`: demo-client
- `redirect_uri`: http://localhost:8080/callback
- `scope`: read
- `code_challenge`: SHA256 hash of PKCE verifier
- `code_challenge_method`: S256

### Step 2: User authentication
The authorization server presents a login form where users authenticate with one of three demo accounts.

### Step 3: Authorization grant
After successful authentication, the authorization server redirects back to the client with an authorization code.

### Step 4: Token exchange
The client exchanges the authorization code for an access token, proving possession of the PKCE verifier.

### Step 5: Resource access
The client uses the access token to access protected resources from the resource server.

## Key OAuth 2.1 features implemented

### PKCE (Proof Key for Code Exchange)
- **Code Verifier**: Cryptographically random 43-character string
- **Code Challenge**: Base64url-encoded SHA256 hash of the verifier
- **Challenge Method**: S256 (SHA256)

### Security improvements over OAuth 2.0
- PKCE is mandatory for all clients
- No support for implicit flow
- Authorization codes are single-use and time-limited
- Access tokens have configurable expiration

## Message logging

All OAuth messages are logged with color-coded output showing:
- Timestamp and direction (→ outgoing, ← incoming)
- Source and destination components
- Message type and formatted payload
- PKCE challenges and verification steps

Example log output:
```
[2024-08-15 10:30:15] CLIENT → AUTH-SERVER
Authorization Request:
  client_id: demo-client
  redirect_uri: http://localhost:8080/callback
  scope: read
  code_challenge: xyz123...
```

## Project structure

```
/
├── cmd/
│   ├── auth-server/     # Authorization server main
│   ├── resource-server/ # Resource server main  
│   └── client/          # Client application main
├── internal/
│   ├── auth/           # Authentication logic
│   ├── oauth/          # OAuth 2.1 implementation
│   ├── logger/         # Message logging system
│   └── users/          # User management
├── web/templates/      # HTML templates
├── data/               # Sample user accounts and resources
└── docs/               # Documentation
```

## Demo accounts

Three pre-configured user accounts are available:
- **alice** / password123
- **bob** / secret456  
- **carol** / mypass789

Passwords are bcrypt-hashed for basic security demonstration.

## Learning outcomes

After running this demo, you will understand:

1. **OAuth 2.1 message flow** - Complete request/response cycle
2. **PKCE security mechanism** - How code verifiers prevent authorization code interception
3. **Token-based authorization** - How access tokens authorize resource access
4. **Security considerations** - State parameters, code expiration, token validation
5. **Real-world implementation** - Practical OAuth server and client code

## API endpoints

### Authorization Server (port 8081)
- `GET /authorize` - OAuth authorization endpoint
- `POST /login` - User login form handler
- `POST /token` - Token exchange endpoint

### Resource Server (port 8082)  
- `GET /protected` - Protected resource (requires Bearer token)
- `GET /userinfo` - User information endpoint (requires Bearer token)
- `GET /health` - Health check endpoint

### Client Application (port 8080)
- `GET /` - Start OAuth flow
- `GET /callback` - OAuth callback handler
- `GET /exchange` - Exchange code for token
- `GET /resource` - Access protected resource
- `GET /userinfo` - Get user information
- `GET /status` - Client status

## Next steps

This implementation provides a solid foundation for understanding OAuth 2.1. To extend it further:

1. **Add refresh tokens** with rotation
2. **Implement token introspection** for distributed validation
3. **Add scopes and permissions** for fine-grained access control
4. **Implement client authentication** for confidential clients
5. **Add persistent storage** for production use
6. **Implement additional grant types** (client credentials, device flow)

## Security notes

This is an educational implementation. For production use, consider:
- Persistent token storage with proper cleanup
- Client authentication and registration
- Rate limiting and brute force protection
- Proper error handling and logging
- HTTPS enforcement
- Cross-origin request protection
- Token introspection for distributed systems