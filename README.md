# Inori
[![WTFPL](https://www.wtfpl.net/wp-content/uploads/2012/12/wtfpl-badge-4.png)](http://www.wtfpl.net/)


A lightweight, self-hosted secrets manager inspired by HashiCorp Vault. Inori securely stores secrets in a LibSQL database, encrypts them with AES-256, and provides optional Redis-based caching and rate limiting. It is designed for simplicity, security, and ease of deployment.

## Features

- Secure Storage: Secrets are encrypted using AES-256 before being stored in the database.
- LibSQL Backend: Uses LibSQL for persistent, reliable storage.
- Redis Caching (Optional): Speeds up secret retrieval and enables distributed rate limiting.
- Rate Limiting: Protects against abuse (30 requests/minute per IP by default).
- Audit Logging: All actions are logged for traceability.
- Simple HTTP API: Easy to integrate with any system.
- Docker Support: Quick to run locally or in production.

## Installation

1. Clone the repository:

```bash
git clone https://github.com/SooditK/inori.git
cd inori
```

2. Create a `.env` file:

```bash
cp .env.example .env
```

3. Get the environment variables (MASTER_SECRET_KEY & SECRETS_API_TOKEN)

```bash
openssl rand -hex 32 # MASTER_SECRET_KEY
openssl rand -hex 32 # SECRETS_API_TOKEN
```

4. Start the service:

```bash
docker compose up -d
```
The service will be available at http://localhost:8080.

OR Run the service locally:

```bash
go run main.go
```

The service will be available at http://localhost:8080.

## Usage

### Authorization

Authorization: `<your SECRETS_API_TOKEN>`


### Get a secret
GET /get?key=<key>

### Set a secret
POST /set?key=<key>&value=<value>

### Delete a secret
DELETE /delete?key=<key>

## Example

```bash
curl -X POST "http://localhost:8080/set?key=MY_SECRET&value=supersecret" -H "Authorization: your_api_token"
curl "http://localhost:8080/get?key=MY_SECRET" -H "Authorization: your_api_token"
curl -X DELETE "http://localhost:8080/delete?key=MY_SECRET" -H "Authorization: your_api_token"
```

## Environment Variables

- `MASTER_SECRET_KEY`: The master secret key used to encrypt and decrypt secrets.
- `SECRETS_API_TOKEN`: The API token used to authenticate requests.
- `LIBSQL_DB_URL`: The URL of the LibSQL database.
- `LIBSQL_DB_AUTH_TOKEN`: The authentication token for the LibSQL database.
- `REDIS_URL`: The URL of the Redis server.

## How It Works

- Encryption: Secrets are encrypted with AES-256-GCM before storage.
- Storage: Encrypted secrets are stored in LibSQL.
- Caching: If Redis is configured, secrets are cached for faster reads.
- Rate Limiting: Each IP is limited to 30 requests per minute (configurable in code).
- Audit Logging: All actions (read, write, delete) are logged in the database.

## Security Notes

- Never share your MASTER_SECRET_KEY or SECRETS_API_TOKEN.
- Use HTTPS in production to protect secrets in transit.
- Rotate your API token and master key periodically.
- Audit logs are stored in the database for traceability.