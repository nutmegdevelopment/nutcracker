# Nutcracker

Nutcracker is a simple and secure credential management system, designed for use in rapidly changing environments where other solutions man not be appropriate.

It has a simple JSON api, and requires no configuration other than environment variables, as it's designed to be run in a container.

## API documentation

| URL              | Method | Required elements | Auth header required? | Description                                                        |
|------------------|--------|-------------------|-----------------------|--------------------------------------------------------------------|
| /health          | GET    |                   | No                    | Healthcheck                                                        |
| /initialise      | GET    |                   | No                    | Set up vault credentials                                           |
| /unseal          | GET    | key               | Yes                   | Unlock vault so that secrets can be created                        |
| /seal            | GET    |                   | No                    | Lock vault to prevent secret creation                              |
| /secrets/message | POST   | name, message     | Yes                   | Create new secret                                                  |
| /secrets/key     | GET    |                   | Yes                   | Create new key                                                     |
| /secrets/share   | POST   | name, key_id, key | Yes                   | Share a secret with a key for later retrieval                      |
| /secrets/view    | POST   | name              | Yes                   | Retrieve a secret shared with your authentication key |

## Authentication

When you intialise the vault, a master key will be created.
This will allow you to create new keys to distribute to users, and can be used to unseal the vault if the server is restarted, or the vault is sealed.

Authentication for calls that require it is done by including the following headers:
```X-Secret-ID: your key name```
```X-Secret-Key: your secret key```

## Configuration

The server requires a postgres database, which is configured using the environment variables here: http://www.postgresql.org/docs/9.4/static/libpq-envars.html
It also supports the following variables:

| Variable | Description |
|----------|-------------|
| SSL_CERT | Path to ssl cert.  If empty, the server with generate a self-signed one. |
| SSL_KEY  | Path to ssl cert.  If empty, the server with generate one. |
| LISTEN   | Address to listen on.  Uses 0.0.0.0:8080 by default. |
