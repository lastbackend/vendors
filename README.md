# Vendors for Go

## Installation

~~~~
go get github.com/lastbackend/vendors
~~~~

## Usage ##

```go
import "github.com/lastbackend/vendors"
```

Get client for github
```go
var client = vendors.GetGitHub(clientID, clientSecretID, redirectURI)
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
