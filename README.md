# OAuth 2.1 Learning Project

A complete implementation of the OAuth 2.1 authorization code flow with PKCE in Go, designed for educational purposes to understand OAuth message exchanges and security mechanisms.

## Table of contents

- [Project overview](#project-overview)
- [Architecture](#architecture)
- [Quick start](#quick-start)
- [Step-by-step OAuth 2.1 flow walkthrough](#step-by-step-oauth-21-flow-walkthrough)
- [Understanding the components](#understanding-the-components)
- [OAuth 2.1 vs OAuth 2.0](#oauth-21-vs-oauth-20)
- [Security features](#security-features)
- [Message logging](#message-logging)
- [Troubleshooting](#troubleshooting)
- [Learning outcomes](#learning-outcomes)
- [API reference](#api-reference)
- [Next steps](#next-steps)

## Project overview

This project demonstrates the OAuth 2.1 authorization code flow through three interconnected applications that communicate using standard OAuth protocols. It's designed to provide hands-on learning about OAuth security mechanisms, message exchanges, and implementation patterns.

### Purpose

- **Educational**: Learn OAuth 2.1 concepts through practical implementation
- **Visual**: See all OAuth messages with detailed logging and color coding
- **Complete**: Experience the full flow from authorization to resource access
- **Secure**: Implement modern OAuth 2.1 security features like mandatory PKCE

### Target audience

- Developers learning OAuth 2.1 implementation
- Engineers implementing OAuth in MCP servers or other applications
- Anyone wanting to understand OAuth message flows and security

## Architecture

The system consists of three independent applications:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Client App    │    │ Authorization    │    │ Resource Server │
│   (Port 8080)   │    │ Server           │    │   (Port 8083)   │
│                 │    │ (Port 8081)      │    │                 │
│ • Initiates     │    │ • User login     │    │ • Protected     │
│   OAuth flow    │    │ • Issues tokens  │    │   resources     │
│ • PKCE          │    │ • PKCE           │    │ • Token         │
│   generation    │    │   verification   │    │   validation    │
│ • Token         │    │ • User           │    │ • Resource      │
│   exchange      │    │   management     │    │   serving       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Component responsibilities

- **Client Application**: Web interface that initiates OAuth flows and consumes protected resources
- **Authorization Server**: Handles user authentication, authorization, and token issuance
- **Resource Server**: Protects and serves resources to properly authorized clients

## Quick start

### Prerequisites

- Go 1.21+ installed
- Three available ports: 8080, 8081, 8083

### Installation and setup

1. **Clone and prepare:**
   ```bash
   git clone <repository-url>
   cd oauth-go
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

3. **Access the demo:**
   - Open browser to http://localhost:8080
   - Follow the OAuth flow using demo credentials

### Demo accounts

Three pre-configured accounts are available:
- **alice** / password123
- **bob** / secret456  
- **carol** / mypass789

## Step-by-step OAuth 2.1 flow walkthrough

Follow this detailed walkthrough to understand each step of the OAuth 2.1 authorization code flow:

### Step 1: Start the OAuth flow

1. **Visit the client application** at http://localhost:8080
2. **Observe the initial screen** showing:
   - Client details (ID, redirect URI, scope)
   - Generated PKCE challenge details
   - "Start OAuth Flow" button

**What happens behind the scenes:**
```go
// Client generates PKCE challenge
pkce, _ := oauth.GeneratePKCEChallenge()
// Creates: 
// - Code Verifier: 43-character random string
// - Code Challenge: SHA256 hash of verifier (Base64url encoded)
```

**Console output:**
```
[2024-08-15 10:30:15] CLIENT → USER-BROWSER
Authorization URL Generated:
  authorization_url: http://localhost:8081/authorize?...
  pkce_challenge: xyz123...
  pkce_method: S256
```

### Step 2: Authorization request

1. **Click "Start OAuth Flow"**
2. **Browser redirects** to authorization server with parameters:
   - `client_id=demo-client`
   - `redirect_uri=http://localhost:8080/callback`
   - `scope=read`
   - `state=demo-state-123`
   - `code_challenge=<SHA256_hash>`
   - `code_challenge_method=S256`

**Console output (Authorization Server):**
```
[2024-08-15 10:30:16] CLIENT → AUTH-SERVER
Authorization Request:
  client_id: demo-client
  redirect_uri: http://localhost:8080/callback
  scope: read
  state: demo-state-123
  code_challenge: xyz123...
  code_challenge_method: S256
  response_type: code
```

### Step 3: User authentication

1. **Login form appears** showing:
   - Application request details
   - OAuth parameters
   - Username/password fields
   - Demo account credentials

2. **Enter credentials** (e.g., alice / password123)

3. **Submit the form**

**What happens behind the scenes:**
```go
// Server validates credentials using bcrypt
user, err := userStore.Authenticate(username, password)
// If successful, generates authorization code
code, _ := oauth.GenerateRandomString(32)
```

**Console output (Authorization Server):**
```
[2024-08-15 10:30:45] USER → AUTH-SERVER
Login Attempt:
  username: alice
  password: [REDACTED]
```

### Step 4: Authorization grant

1. **Successful authentication** triggers redirect back to client
2. **Authorization code** is appended to redirect URI
3. **Browser returns** to http://localhost:8080/callback?code=xyz&state=demo-state-123

**Console output (Authorization Server):**
```
[2024-08-15 10:30:46] AUTH-SERVER → CLIENT
Authorization Response:
  code: abc123...
  state: demo-state-123
```

**Console output (Client):**
```
[2024-08-15 10:30:46] AUTH-SERVER → CLIENT
Authorization Callback:
  code: abc123...
  state: demo-state-123
  error: 
```

### Step 5: Display authorization code

1. **Client processes callback** and shows:
   - "Authorization Code Received" message
   - The actual authorization code
   - "Exchange Code for Token" button

**What happens behind the scenes:**
```go
// Client stores the authorization code for later use
c.authCode = code
```

### Step 6: Token exchange

1. **Click "Exchange Code for Token"**
2. **Client sends POST request** to token endpoint with:
   - `grant_type=authorization_code`
   - `code=<authorization_code>`
   - `redirect_uri=http://localhost:8080/callback`
   - `client_id=demo-client`
   - `code_verifier=<original_43_char_string>`

**Console output (Client):**
```
[2024-08-15 10:31:00] CLIENT → AUTH-SERVER
Token Exchange Request:
  grant_type: authorization_code
  redirect_uri: http://localhost:8080/callback
  client_id: demo-client
  code_verifier: cQpV8MttKOP6c0zDhnTN...
```

**What happens behind the scenes (Authorization Server):**
```go
// 1. Retrieve stored authorization code
authCode, err := store.GetAuthorizationCode(code)

// 2. Verify PKCE challenge
if !oauth.VerifyPKCE(codeVerifier, authCode.CodeChallenge, "S256") {
    return "invalid_grant"
}

// 3. Generate access token
accessToken, _ := oauth.GenerateRandomString(32)
```

**Console output (Authorization Server):**
```
[2024-08-15 10:31:01] AUTH-SERVER → CLIENT
Token Response:
  access_token: def456...
  token_type: Bearer
  expires_in: 3600
  scope: read
```

### Step 7: Access token received

1. **Client displays success** showing:
   - "Access Token Received" message
   - The access token value
   - "Access Protected Resource" button
   - "Get User Info" button

### Step 8: Access protected resource

1. **Click "Access Protected Resource"**
2. **Client sends GET request** to resource server with:
   - `Authorization: Bearer <access_token>` header

**Console output (Client):**
```
[2024-08-15 10:31:15] CLIENT → RESOURCE-SERVER
Protected Resource Request:
  Headers:
    Authorization: Bearer def456...
```

**What happens behind the scenes (Resource Server):**
```go
// 1. Extract Bearer token from Authorization header
token := strings.TrimPrefix(authHeader, "Bearer ")

// 2. Validate token (in this demo, simplified validation)
accessToken, err := validateToken(token)

// 3. Serve protected resource
content, _ := os.ReadFile("data/protected-resource.txt")
```

**Console output (Resource Server):**
```
[2024-08-15 10:31:15] CLIENT → RESOURCE-SERVER
Resource Request:
  path: /protected
  method: GET
  Headers:
    Authorization: Bearer def456...

[2024-08-15 10:31:15] RESOURCE-SERVER → RESOURCE-SERVER
Token Validation Success:
  user_id: validated-user
  client_id: demo-client
  scope: read

[2024-08-15 10:31:15] RESOURCE-SERVER → CLIENT
Protected Resource Response:
  resource_size: 1234
  content_type: text/plain
```

### Step 9: Resource delivered

1. **Client displays the protected resource** content
2. **Flow complete!** User has successfully:
   - Authenticated with the authorization server
   - Authorized the client application
   - Received an access token
   - Accessed protected resources

## Understanding the components

### Authorization server (`cmd/auth-server/`)

**Key responsibilities:**
- User authentication and session management
- Authorization code generation and storage
- PKCE challenge verification
- Access token issuance
- Security validation (redirect URIs, client IDs, etc.)

**Key endpoints:**
- `GET /authorize` - OAuth authorization endpoint
- `POST /login` - Processes user credentials
- `POST /token` - Token exchange endpoint

**Security features:**
- Bcrypt password hashing
- Authorization code expiration (10 minutes)
- PKCE mandatory verification
- State parameter validation

### Resource server (`cmd/resource-server/`)

**Key responsibilities:**
- Access token validation
- Protected resource serving
- Authorization enforcement
- User information provision

**Key endpoints:**
- `GET /protected` - Protected file resource
- `GET /userinfo` - User information endpoint
- `GET /health` - Health check

**Security features:**
- Bearer token validation
- Proper HTTP status codes
- WWW-Authenticate headers

### Client application (`cmd/client/`)

**Key responsibilities:**
- OAuth flow initiation
- PKCE generation and verification
- Authorization code handling
- Token management
- Resource consumption

**Key endpoints:**
- `GET /` - Start OAuth flow
- `GET /callback` - OAuth callback handler
- `GET /exchange` - Token exchange trigger
- `GET /resource` - Access protected resource
- `GET /userinfo` - Get user information

**Security features:**
- PKCE implementation
- State parameter verification
- Secure token storage
- Proper error handling

## OAuth 2.1 vs OAuth 2.0

This implementation showcases key OAuth 2.1 improvements:

### Mandatory PKCE
- **OAuth 2.0**: PKCE optional for public clients
- **OAuth 2.1**: PKCE mandatory for all clients
- **Security benefit**: Prevents authorization code interception attacks

### No implicit flow
- **OAuth 2.0**: Supports implicit flow (tokens in URL fragments)
- **OAuth 2.1**: Implicit flow removed
- **Security benefit**: Eliminates token exposure in browser history/logs

### Enhanced security defaults
- **OAuth 2.0**: Various security features optional
- **OAuth 2.1**: Security-first approach with mandatory protections
- **Security benefit**: Reduced attack surface by default

## Security features

### PKCE (Proof Key for Code Exchange)

**Purpose**: Prevents authorization code interception attacks

**Implementation**:
1. **Code Verifier**: 43-character cryptographically random string
2. **Code Challenge**: Base64url-encoded SHA256 hash of verifier
3. **Challenge Method**: S256 (SHA256)

**Flow**:
```
Client generates: verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
Client sends: challenge = SHA256(verifier) = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
Client proves: verifier matches challenge during token exchange
```

### State parameter validation

**Purpose**: Prevents CSRF attacks

**Implementation**: Random state value maintained between authorization request and callback

### Authorization code expiration

**Purpose**: Limits window for code interception

**Implementation**: Codes expire after 10 minutes

### Password security

**Purpose**: Protect user credentials

**Implementation**: Bcrypt hashing with default cost (10 rounds)

## Message logging

All OAuth messages are logged with detailed, color-coded output:

### Log format
```
[timestamp] SOURCE DIRECTION DESTINATION
Message Type:
  parameter: value
  parameter: value
  Headers:
    header: value
--------------------------------------------------
```

### Color coding
- **Blue**: Client messages
- **Green**: Authorization server messages  
- **Yellow**: Resource server messages
- **Red**: Error messages
- **Cyan**: Info messages

### Example log sequence
```
[2024-08-15 10:30:15] CLIENT → AUTH-SERVER
Authorization Request:
  client_id: demo-client
  scope: read
  code_challenge: xyz123...

[2024-08-15 10:30:46] AUTH-SERVER → CLIENT  
Authorization Response:
  code: abc123...
  state: demo-state-123

[2024-08-15 10:31:01] CLIENT → AUTH-SERVER
Token Exchange Request:
  grant_type: authorization_code
  code_verifier: cQpV8MttKOP6c0zDhnTN...

[2024-08-15 10:31:01] AUTH-SERVER → CLIENT
Token Response:
  access_token: def456...
  token_type: Bearer
  expires_in: 3600
```

## Troubleshooting

### Common issues

**"invalid credentials" for all users**
- **Cause**: Incorrect bcrypt hashes
- **Solution**: Use `go run cmd/hash-passwords/main.go` to generate new hashes

**"authorization code not found"**
- **Cause**: Code not properly stored or expired
- **Solution**: Complete flow within 10 minutes, check client code storage

**"PKCE verification failed"**
- **Cause**: Code verifier doesn't match challenge
- **Solution**: Ensure PKCE challenge is properly stored between requests

**Port already in use**
- **Cause**: Another process using the port
- **Solution**: Find with `lsof -i :8080` and kill, or change port in code

**Template not found**
- **Cause**: Running from wrong directory
- **Solution**: Run from project root where `web/templates/` exists

### Debug tips

1. **Check all three servers are running** on correct ports
2. **Watch console logs** for detailed OAuth message flows
3. **Verify demo accounts** with password hashing utility
4. **Clear browser cache** if experiencing unexpected redirects
5. **Use browser developer tools** to inspect network requests

### Log analysis

**Successful flow pattern:**
```
Authorization Request → Authorization Response → Token Request → Token Response → Resource Request → Resource Response
```

**Failed authentication:**
```
Authorization Request → Login Attempt → ERROR: Invalid credentials
```

**PKCE failure:**
```
Authorization Request → Authorization Response → Token Request → ERROR: PKCE verification failed
```

## Learning outcomes

After completing this walkthrough, you will understand:

### OAuth 2.1 concepts
- Authorization code flow with PKCE
- Client types and security considerations
- Token-based authorization
- Scope and permissions

### Security mechanisms
- PKCE prevents code interception
- State parameter prevents CSRF
- Proper token validation
- Secure credential handling

### Implementation patterns
- Multi-component OAuth architecture
- HTTP redirects and callbacks
- Token exchange protocols
- Error handling strategies

### Real-world considerations
- Token expiration and refresh
- Scope validation
- Client authentication
- Production security requirements

## API reference

### Authorization server endpoints

#### GET /authorize
**Purpose**: OAuth 2.1 authorization endpoint

**Parameters**:
- `client_id` (required): Client identifier
- `redirect_uri` (required): Callback URL
- `scope` (required): Requested permissions
- `state` (required): CSRF protection
- `code_challenge` (required): PKCE challenge
- `code_challenge_method` (required): Must be "S256"
- `response_type` (required): Must be "code"

**Response**: HTML login form or redirect to callback

#### POST /login
**Purpose**: Process user authentication

**Parameters** (form data):
- `username` (required): User identifier
- `password` (required): User password
- OAuth parameters from authorization request

**Response**: Redirect to client callback with authorization code

#### POST /token
**Purpose**: Exchange authorization code for access token

**Parameters** (form data):
- `grant_type` (required): Must be "authorization_code"
- `code` (required): Authorization code from callback
- `redirect_uri` (required): Must match authorization request
- `client_id` (required): Client identifier
- `code_verifier` (required): PKCE verifier

**Response**: JSON with access token

### Resource server endpoints

#### GET /protected
**Purpose**: Serve protected resource

**Headers**:
- `Authorization: Bearer <access_token>` (required)

**Response**: Protected file content

#### GET /userinfo
**Purpose**: Provide user information

**Headers**:
- `Authorization: Bearer <access_token>` (required)

**Response**: JSON with user details

#### GET /health
**Purpose**: Health check endpoint

**Response**: JSON with server status

### Client endpoints

#### GET /
**Purpose**: Start OAuth flow

**Response**: HTML with authorization URL and PKCE details

#### GET /callback
**Purpose**: Handle OAuth callback

**Parameters**:
- `code`: Authorization code (success case)
- `error`: Error code (error case)
- `state`: CSRF protection value

**Response**: HTML showing code or error

#### GET /exchange
**Purpose**: Trigger token exchange

**Response**: HTML showing access token or error

#### GET /resource
**Purpose**: Access protected resource

**Response**: HTML showing resource content

#### GET /userinfo
**Purpose**: Get user information

**Response**: HTML showing user details

## Next steps

### Extend the implementation

1. **Add refresh tokens** with rotation:
   ```go
   type TokenResponse struct {
       AccessToken  string `json:"access_token"`
       RefreshToken string `json:"refresh_token"`
       ExpiresIn    int64  `json:"expires_in"`
   }
   ```

2. **Implement token introspection** (RFC 7662):
   ```go
   // POST /introspect
   func (as *AuthServer) introspect(w http.ResponseWriter, r *http.Request) {
       token := r.FormValue("token")
       // Validate and return token metadata
   }
   ```

3. **Add scopes and permissions**:
   ```go
   type Scope struct {
       Name        string
       Description string
       Resources   []string
   }
   ```

4. **Implement client authentication**:
   ```go
   type Client struct {
       ID           string
       Secret       string
       RedirectURIs []string
       Type         string // "public" or "confidential"
   }
   ```

### Production considerations

1. **Persistent storage**: Replace in-memory stores with databases
2. **Rate limiting**: Implement brute force protection
3. **Audit logging**: Track all security events
4. **HTTPS enforcement**: Never run OAuth over HTTP in production
5. **CORS handling**: Properly configure cross-origin policies
6. **Token introspection**: Enable distributed token validation
7. **Client registration**: Dynamic client registration (RFC 7591)
8. **Device flow**: Support for devices without browsers (RFC 8628)

### Integration patterns

1. **API Gateway integration**: Token validation at gateway level
2. **Microservices**: Distributed token validation
3. **Single Sign-On**: Multiple client applications
4. **Mobile applications**: Native app integration patterns
5. **Third-party providers**: Integration with external OAuth providers

This project provides a solid foundation for understanding OAuth 2.1 and implementing secure authorization systems in production environments.