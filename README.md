# OAuth2 CLI Server – Complete Documentation

## Table of Contents

- [Installation Build](#installation-build)
  - [Prerequisites](#prerequisites)
  - [Build](#build)
- [Configuration](#configuration)
- [Data](#data)
- [API](#api)
  - [POST /token](#post-token)
    - [Grant Type: client_credentials](#grant-type-client_credentials)
  - [POST /token/refresh](#post-tokenrefresh)
  - [POST /api/payments](#post-apipayments)
  - [POST /revoke](#post-revoke)
  - [POST /introspect](#post-introspect)
- [Error Codes](#error-codes)
- [Token Format](#token-format)
  - [Access Token](#access-token)
  - [Refresh Token](#refresh-token)
- [Interactive Test Client (Python)](#interactive-test-client-python)
  - [Usage](#usage)
  - [Menu](#menu)
  - [Requirements](#requirements)
- [User Manual](#user-manual)

- **Authorization Server** – handles:
  - `/token` – token issuance
  - `/token/refresh` – refresh token rotation
  - `/revoke` – token revocation
  - `/introspect` – token introspection

- **Resource Server** – handles:
  - `/api/payments` – protected resource access


# Installation Build

# Prerequisites

Building for macbook air m4 apple sillicon. macOS Tahoe 26.2

1. Qt (Core module) – version 5 or 6.
2. OpenSSL – for HMAC-SHA256 signatures.
3. CMake – version 3.16 or higher.
4. A C++20 compiler (GCC, Clang, MSVC).
5. python3 (I'm using python3.12 currently)

# Build
```bash
git clone <repository-url>
cd cpp-mini-oauth2
./build.sh
```

The executable cli-server will be placed in build/.

# Configuration
The server reads its settings from config/auth.json. If the file does not exist, default values are used.
Example auth.json is in config/auth.json and is:
```json
{
    "issuer": "mini-auth", # Issuer claim in JWT
    "auth_secret": "supersecret", # Secret key for HMAC‑SHA256 signing
    "access_ttl_sec": 900, # Access token lifetime (seconds)
    "refresh_ttl_days": 14, # Refresh token lifetime (days)
    "clock_skew_sec": 60 # Allowed clock skew (seconds) for validation
}
```

# Data
All data is stored in data/
Examples:

1. users.json
Schema
```json
[
  {
    "user_id": "string",
    "username": "string",
    "password_hash": "string",
    "roles": ["string"],
    "status": "active | inactive"
  }
]
```

Example
```json
[
  {
    "user_id": "u-100",
    "username": "alice",
    "password_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
    "roles": ["manager", "viewer"],
    "status": "active"
  }
]
```

2. clients.json
Schema
```json
[
  {
    "client_id": "string",
    "client_secret": "string",
    "allowed_grants": ["password", "client_credentials", "refresh_token"],
    "allowed_scopes": ["string"],
    "aud": "string"
  }
]
```

Example
```json
[
  {
    "client_id": "cli-001",
    "client_secret": "secret",
    "allowed_grants": ["password", "client_credentials", "refresh_token"],
    "allowed_scopes": ["payments:read", "payments:write", "users:read"],
    "aud": "payments-api"
  }
]
```

3. roles.json
Schema
```json
{
  "role_name": {
    "scopes": ["string"]
  }
}
```

Example
```json
{
  "admin":   { "scopes": ["*"] },
  "manager": { "scopes": ["payments:read", "payments:write"] },
  "viewer":  { "scopes": ["payments:read"] }
}
```

4. refresh_index.ndjson
Schema
```json
{
  "refresh_token": "string",
  "user_id": "string",
  "client_id": "string",
  "scopes": ["string"],
  "exp": 1234567890,
  "rotated": false
}
```

5. revocations.json
Schema
```json
{
  "type": "access | refresh",
  "token_id": "string (jti or refresh_token)",
  "exp": 1234567890
}
```

# API

Command format:

```bash
./build/cli-server <endpoint> <input.json> <output.json>
```

## POST /token

- Request:
```json
{
  "grant_type": "password",
  "username": "alice",
  "password": "password",
  "client_id": "cli-001",
  "client_secret": "secret",
  "scopes": ["payments:read", "payments:write"]
}
```
- Success Response (HTTP 200):

```json
{
  "access_token": "<JWT>",
  "refresh_token": "<uuid>",
  "token_type": "Bearer",
  "expires_in": 900
}
```
- Error Response (e.g., invalid credentials):

```json
{
  "error": "invalid_grant",
  "error_description": "Invalid username or password"
}
```
### Grant Type: client_credentials

- Request:

```json
{
  "grant_type": "client_credentials",
  "client_id": "cli-001",
  "client_secret": "secret",
  "scopes": ["payments:read"]
}
```

- Success Response (HTTP 200):

```json
{
  "access_token": "<JWT>",
  "token_type": "Bearer",
  "expires_in": 900
}
```

- No refresh token is issued for client_credentials.

## POST /token/refresh

Exchanges a valid refresh token for a new access token (and a new refresh token). The old refresh token is marked as rotated and becomes invalid.

- Request:

```json
{
  "grant_type": "refresh_token",
  "refresh_token": "<refresh_token>",
  "client_id": "cli-001",
  "client_secret": "secret"
}
```

- Success Response (HTTP 200):
```json
{
  "access_token": "<JWT>",
  "refresh_token": "<new_uuid>",
  "token_type": "Bearer",
  "expires_in": 900
}
```

- Error Response (e.g., expired or rotated refresh token):

```json
{
  "error": "invalid_grant",
  "error_description": "Refresh token already used (rotated)"
}
```

## POST /api/payments

Protected resource endpoint that requires a valid access token with the appropriate scope.

- Request:

```json
{
  "access_token": "<access_token>",
  "method": "GET"   // or "POST"
}
```

- GET – requires the payments:read scope.
- POST – requires the payments:write scope.
- Success Response (HTTP 200):

```json
{
  "status": "success",
  "message": "Access granted to payments resource",
  "user_id": "u-100",
  "data": "List of payments (dummy)"
}
```

- Error Response (missing scope):

```json
{
  "error": "insufficient_scope",
  "error_description": "Required scope missing: payments:write"
}
```

- Error Response (invalid token):

```json
{
  "error": "invalid_token",
  "error_description": "Token validation failed"
}
```
## POST /revoke

Revokes an access token (by JTI) or a refresh token (by token string). The operation is idempotent.

- Request:

```json
{
  "token": "<access_token_or_refresh_token>",
  "token_type_hint": "access_token"   // or "refresh_token" (optional)
}
```
If token_type_hint is omitted, the server attempts to detect the type.

- Success Response (HTTP 200):

```json
{
  "status": "success"
}
```

- Error Response (e.g., token not found):

```json
{
  "error": "invalid_token",
  "error_description": "Refresh token not found"
}
```

## POST /introspect
Checks the status of an access token and returns its metadata if active.

- Request:

```json
{
  "token": "<access_token>"
}
```
- Response (active):

```json
{
  "active": true,
  "client_id": "cli-001",
  "sub": "u-100",
  "scope": "payments:read payments:write",
  "roles": ["manager", "viewer"],
  "exp": 1737260000,
  "iat": 1737259100,
  "jti": "uuid"
}
```

- Response (inactive):
```json
{
  "active": false
}
```
# Error Codes

All endpoints return JSON responses with error and error_description fields on failure.

Error Code             | Description
invalid_client         | Client ID or secret is incorrect.
invalid_grant          | Invalid username/password, expired refresh token, etc.
invalid_token          | Token validation failed (signature, expiry, etc.).
insufficient_scope     | Token does not have the required scope.
unsupported_grant_type | Unknown grant_type value.
unauthorized_client	   | Client is not allowed to use the requested grant type.
invalid_request        | Missing required fields (e.g., token).
server_error           | Internal server error (logged to stderr).

# Token Format

## Access Token

The access token is a JSON Web Token (JWT) signed with HMAC‑SHA256 using the auth_secret. It contains the following claims:

typ – "AT" (Access Token)
alg – "HS256"
iss – issuer (from config)
aud – audience (from client's aud)
sub – user ID (or client ID for client_credentials)
client_id – client ID
scopes – array of granted scopes
roles – array of user roles
iat – issued at (UNIX timestamp)
exp – expiration time (UNIX timestamp)
jti – unique token identifier (UUID)

- Example (decoded):

```json
{
  "typ": "AT",
  "alg": "HS256",
  "iss": "mini-auth",
  "aud": "payments-api",
  "sub": "u-100",
  "client_id": "cli-001",
  "scopes": ["payments:read", "payments:write"],
  "roles": ["manager", "viewer"],
  "iat": 1737259100,
  "exp": 1737260000,
  "jti": "550e8400-e29b-41d4-a716-446655440000"
}
```

## Refresh Token

The refresh token is an opaque UUID string (without dashes by default). It is stored in refresh_index.ndjson along with its associated metadata.

# Interactive Test Client (Python)

A Python script test_interactive.py is provided to run all test scenarios interactively. It maintains access/refresh tokens across calls and displays formatted JSON.

## Usage

```bash
chmod +x test_interactive.py
./test_interactive.py
```

# Menu

```text
============================================================
               OAuth2 Test Scenarios                         
============================================================
  1. Password Grant (obtain tokens)
  2. Client Credentials Grant
  3. Refresh Token Rotation
  4. Resource Server GET (payments:read)
  5. Resource Server POST (payments:write)
  6. Revoke Access Token
  7. Token Introspection
  8. Access with Revoked Token (should fail)
  9. Run ALL scenarios in sequence
  0. Exit
============================================================
Choose an option (0-9):
```

# Requirements
1. Python 3.12+
2. The CLI server built at ./build/cli-server

# User Manual

1. Prepare Data – ensure data/users.json, data/clients.json, and data/roles.json exist with at least one user, client, and role definitions.
2. Start Testing – use the interactive test clients (Python or Bash) to run predefined scenarios.
3. Manual Request – to make a custom request, create a JSON file and run:

```bash
./build/cli-server /token my_request.json my_response.json
```

Inspect Responses – check the output JSON file for the response.

Example: Obtaining a Token with curl-like Behavior

Since the server is CLI-based, you can simulate a curl request using a temporary file:

```bash
echo '{"grant_type":"password","username":"alice","password":"password","client_id":"cli-001","client_secret":"secret","scopes":["payments:read"]}' > req.json
./build/cli-server /token req.json resp.json
cat resp.json
```
