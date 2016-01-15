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