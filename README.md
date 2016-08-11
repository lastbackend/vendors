# OAuth2 for Go

## Installation

~~~~
go get golang.org/lastbackend/oauth2
~~~~

## Usage ##

```go
import "github.com/lastbackend/oauth2"
```

Get client for vendor type
```go
client, err := oauth2.GetClient(vendor, clientID, clientSecretID, redirectURI)
if err != nil {
    return err
}
```

Get token using auth code
```go
token, err := client.GetToken(code)
if err != nil {
    return err
}
```

Get user information use token
```go
user, err := client.GetUser(token)
if err != nil {
    return err
}
```