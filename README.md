# Nutcracker

Nutcracker is a simple and secure credential management system, designed for use in rapidly changing environments where other solutions man not be appropriate.

It has a simple JSON api, and requires no configuration other than environment variables, as it's designed to be run in a container.

## API documentation

| URL              | Method | Required elements | Description                                                        |
|------------------|--------|-------------------|--------------------------------------------------------------------|
| /health          | GET    |                   | Healthcheck                                                        |
| /initialise      | GET    |                   | Set up vault credentials                                           |
| /unseal          | POST   | key               | Unlock vault so that secrets can be added                          |
| /seal            | GET    |                   | Lock vault to prevent secrets from being added                     |
| /secrets/message | POST   | name, message     | Create new secret                                                  |
| /secrets/key     | GET    |                   | Create new key                                                     |
| /secrets/share   | POST   | name, key_id      | Share a secret with a key for later retrieval                      |
| /secrets/get     | GET    | name, key         | Retrieve a secret using a key that the secret has been shared with |