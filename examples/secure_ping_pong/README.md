# Secure Ping Pong (Go)

This example demonstrates the **SimpleGuard** security strategy using the `capiscio-core` Go library.

It consists of:
1.  **Server**: A simple HTTP server protected by `simpleguard.Middleware`.
2.  **Client**: A CLI tool that signs requests using `simpleguard.SignOutbound`.

## Prerequisites

- Go 1.21+

## Running the Example

### 1. Start the Server

Open a terminal and run:

```bash
cd server
go run main.go
```

You should see:
```
🛡️  Secure Ping Pong Server running on :8080
   Waiting for signed requests...
```

### 2. Run the Client

Open a second terminal and run:

```bash
cd client
go run main.go
```

You should see output demonstrating:
1.  **Valid Request**: Successfully verified and processed.
2.  **Tampered Body**: Blocked by the middleware (Integrity Check).

## How it Works

1.  **Zero Config**: Both client and server use `DevMode: true`, which auto-generates ephemeral Ed25519 keys on startup.
2.  **Identity**: The client signs the request with its private key.
3.  **Integrity**: The client includes a hash of the body (`bh` claim) in the token.
4.  **Verification**: The server middleware:
    - Verifies the signature.
    - Checks `iat` and `exp` timestamps (Freshness).
    - Hashes the received body and compares it to the `bh` claim (Integrity).
