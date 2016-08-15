package bitbucket

import (
	"encoding/json"
	"golang.org/x/oauth2"
	"time"
	"model"
)

type Bitbucket struct {
	clientID       string
	clientSecretID string
	redirectURI    string
	vendor         string
	host           string
}

func GetClient(clientID, clientSecretID, redirectURI string) (*Bitbucket, error) {
	return &Bitbucket{
		clientID:       clientID,
		clientSecretID: clientSecretID,
		redirectURI:    redirectURI,
		vendor:         "bitbucket",
		host:           "bitbucket.org",
	}, nil
}

func (b Bitbucket) GetToken(code string) (*oauth2.Token, error) {

	conf := b.config()

	token, err := conf.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (b Bitbucket) RefreshToken(token *oauth2.Token) (*oauth2.Token, bool, error) {

	var err error

	if token.Expiry.Before(time.Now()) == false || token.RefreshToken == "" {
		return token, false, nil
	}

	restoredToken := &oauth2.Token{
		RefreshToken: token.RefreshToken,
	}

	c := b.config().Client(oauth2.NoContext, restoredToken)

	newToken, err := c.Transport.(*oauth2.Transport).Source.Token()
	if err != nil {
		return nil, false, err
	}

	return newToken, true, nil
}

func (b Bitbucket) GetUser(token *oauth2.Token) (*model.User, error) {

	var err error

	client := oauth2.NewClient(oauth2.NoContext, oauth2.StaticTokenSource(token))

	payload := struct {
		Username string `json:"username"`
		ID       string `json:"uuid"`
	}{}

	user := new(model.User)

	resUser, err := client.Get("https://api.bitbucket.org/2.0/user")

	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(resUser.Body).Decode(&payload)
	if err != nil {
		return nil, err
	}

	user.Username = payload.Username
	user.ServiceID = payload.ID

	emailsResponse := struct {
		Emails []struct {
			Email     string `json:"email"`
			Confirmed bool   `json:"is_confirmed"`
			Primary   bool   `json:"is_primary"`
		} `json:"values"`
	}{}

	resEmails, err := client.Get("https://api.bitbucket.org/2.0/user/emails")
	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(resEmails.Body).Decode(&emailsResponse)
	if err != nil {
		return nil, err
	}

	for _, email := range emailsResponse.Emails {
		if email.Confirmed == true && email.Primary == true {
			user.Email = email.Email
			break
		}
	}

	return user, nil
}

func (b Bitbucket) GetVendorInfo() *model.Vendor {
	return &model.Vendor{
		Vendor: b.vendor,
		Host:   b.host,
	}
}

func (b Bitbucket) config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     b.clientID,
		ClientSecret: b.clientSecretID,
		RedirectURL:  b.redirectURI,
		Endpoint: oauth2.Endpoint{
			TokenURL: "https://bitbucket.org/site/oauth2/access_token",
		},
	}
}
