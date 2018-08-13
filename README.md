# Nutcracker

Nutcracker is a simple and secure credential management system, designed for use in rapidly changing environments where other solutions may not be appropriate.

It has a simple JSON API, and requires no configuration other than environment variables, as it's designed to be run in a container.

## API documentation

| URL                     | Method | Required elements | Auth header required? | Description                                                        |
|-------------------------|--------|-------------------|-----------------------|--------------------------------------------------------------------|
| /health                 | GET    |                   | No                    | Healthcheck                                                        |
| /initialise             | GET    |                   | No                    | Set up vault credentials                                           |
| /unseal                 | GET    |                   | Yes                   | Unlock vault so that secrets can be created                        |
| /seal                   | GET    |                   | No                    | Lock vault to prevent secret creation                              |
| /auth                   | GET    |                   | Yes                    | Returns account type                              |
| /secrets/message        | POST   | name, message     | Yes                   | Create new secret                                                  |
| /secrets/key            | POST   | admin             | Yes                   | Create new key.  Set the boolean "admin" to true for a key with write access.  Optionally a "name" attribute can be specified to add a named key (otherwise a UUID will be used).      |
| /secrets/share          | POST   | name, keyid       | Yes                   | Share a secret with a key for later retrieval                      |
| /secrets/update         | POST   | name, message     | Yes                   | Update the content of an existing key                              |
| /secrets/view           | POST   | name              | Yes                   | Retrieve a secret shared with your authentication key              |
| /secrets/view/{name}    | GET    | name, secretkey, secretid  | No           | Retrieve a secret shared with your authentication key where {name} is the keyname and secretid and secretkey are url parameters. e.g. /secrets/view/name?secretid=...&secretkey=... (see authentication section for more details). |
| /secrets/list/keys      | GET    |                   | Yes                   | List all keys |
| /secrets/list/keys/{secret} | GET    |                   | Yes                   | List all keys which can read the secret |
| /secrets/list/secrets      | GET    |                   | Yes                   | List all secrets |
| /secrets/list/secrets/{key} | GET    |                   | Yes                   | List all secrets readable by the key |
| /secrets/delete/secrets/{secret} | DELETE    |                   | Yes                   | Delete a secret by name |
| /secrets/delete/key/{key} | DELETE    |                   | Yes                   | Delete a key by name |

## Authentication

When you intialise the vault, a master key will be created.
This will allow you to create new keys to distribute to users, and can be used to unseal the vault if the server is restarted, or if the vault is sealed.

Authentication for calls that require it is done by including the following headers:

```X-Secret-ID: your key name```

```X-Secret-Key: your secret key```

If you are passing the secretkey and secretid on the URL using the /secrets/view/{name} API option then you will need to make sure any '+' or '=' signs in the secret key are url escaped.

To do this you can:

```
echo "my+secret+key+string" | sed s/\+/\%2B/g | sed s/\=/\%3D/g
```

For example, if your key was "your-key" and your secret id was "bc58c7f9-16a3-4869-b27f-1fb3330ada63" and your secret key was "/tNxdZ0GslQYtM7LfyQA/yYm3wPY+EVsLGW1cyPSW+E="

```
echo "/tNxdZ0GslQYtM7LfyQA/yYm3wPY+EVsLGW1cyPSW+E=" | sed s/\+/\%2B/g
```

Would give you a url escaped secret key of:

```
/tNxdZ0GslQYtM7LfyQA/yYm3wPY%2BEVsLGW1cyPSW%2BE%3D
```

With a resulting URL of:

```
/secrets/view/your-key?secretid=bc58c7f9-16a3-4869-b27f-1fb3330ada63&secretkey=/tNxdZ0GslQYtM7LfyQA/yYm3wPY%2BEVsLGW1cyPSW%2BE%3D
```


## Configuration

The server requires a postgres database, which is configured using the environment variables here: http://www.postgresql.org/docs/9.4/static/libpq-envars.html
It also supports the following variables:

| Variable | Description |
|----------|-------------|
| LISTEN   | Address to listen on.  Uses 0.0.0.0:8443 by default. |
| LISTEN_HTTP   | Monitoring port to listen on.  Uses 0.0.0.0:8080 by default. |
| DEBUG    | When set to true, turns on debug logging |

## Tutorial

```
First, initialise the vault:
curl -k https://localhost:8080/initialise

This will return a master key for the vault.  Use it to create your own secret, and store the master somewhere safe.  After this, you'll only need it again when the server restarts.

curl -k -H 'X-Secret-ID: master' -H 'X-Secret-Key: 2IrTBhm3ZNIZZEJxfmj2hrr37+4345cMzBFRvoO2m3E=' https://localhost:8080/secrets/key -d '{"admin": true}'

Now create a new secret message:

curl -k -H 'X-Secret-ID: 1267b254-0855-44e5-9062-627e00b03523' -H 'X-Secret-Key: GadB7QQsZ78K1djnJsIHxsskbJG8AmMd4YQsI7WSpGw=' https://localhost:8080/secrets/message -d '{"name":"test","message": "my-message"}'

Create a read-only key to share this with:

curl -k -H 'X-Secret-ID: 1267b254-0855-44e5-9062-627e00b03523' -H 'X-Secret-Key: GadB7QQsZ78K1djnJsIHxsskbJG8AmMd4YQsI7WSpGw=' https://localhost:8080/secrets/key -d '{"admin": false}'

Share the secret:

curl -k -H 'X-Secret-ID: 1267b254-0855-44e5-9062-627e00b03523' -H 'X-Secret-Key: GadB7QQsZ78K1djnJsIHxsskbJG8AmMd4YQsI7WSpGw=' https://localhost:8080/secrets/share -d '{"name":"test","keyid": "fed6f3b0-2eaf-440f-bfae-fe0100604c48"}'

View the secret with the read-only key:

curl -k -H 'X-Secret-ID: fed6f3b0-2eaf-440f-bfae-fe0100604c48' -H 'X-Secret-Key: RcyRMobQvys4NWvHDZxUFnKa/qggWRqosRhN120exT0=' https://localhost:8080/secrets/view -d '{"name":"test"}'
```
