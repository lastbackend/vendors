package github

import (
	"encoding/json"
	"github.com/lastbackend/vendors/model"
	"golang.org/x/oauth2"
	"strconv"
	"time"
)

type GitHub struct {
	clientID       string
	clientSecretID string
	vendor         string
	host           string
}

func GetClient(clientID, clientSecretID, _ string) (*GitHub, error) {
	return &GitHub{
		clientID:       clientID,
		clientSecretID: clientSecretID,
		vendor:         "github",
		host:           "github.com",
	}, nil
}

func (g GitHub) GetToken(code string) (*oauth2.Token, error) {

	conf := g.config()

	token, err := conf.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (g GitHub) RefreshToken(token *oauth2.Token) (*oauth2.Token, bool, error) {

	var err error

	if token.Expiry.Before(time.Now()) == false || token.RefreshToken == "" {
		return token, false, nil
	}

	restoredToken := &oauth2.Token{
		RefreshToken: token.RefreshToken,
	}

	c := g.config().Client(oauth2.NoContext, restoredToken)

	newToken, err := c.Transport.(*oauth2.Transport).Source.Token()
	if err != nil {
		return nil, false, err
	}

	return newToken, true, nil
}

func (g GitHub) GetUser(token *oauth2.Token) (*model.User, error) {

	var err error

	client := oauth2.NewClient(oauth2.NoContext, oauth2.StaticTokenSource(token))

	payload := struct {
		Username string `json:"login"`
		ID       int64  `json:"id"`
	}{}

	user := new(model.User)

	resUser, err := client.Get("https://api.github.com/user")

	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(resUser.Body).Decode(&payload)
	if err != nil {
		return nil, err
	}

	user.Username = payload.Username
	user.ServiceID = strconv.FormatInt(payload.ID, 10)

	emailsResponse := []struct {
		Email     string `json:"email"`
		Confirmed bool   `json:"verified"`
		Primary   bool   `json:"primary"`
	}{}

	resEmails, err := client.Get("https://api.github.com/user/emails")
	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(resEmails.Body).Decode(&emailsResponse)
	if err != nil {
		return nil, err
	}

	for _, email := range emailsResponse {
		if email.Confirmed == true && email.Primary == true {
			user.Email = email.Email
			break
		}
	}

	return user, nil
}

func (g GitHub) GetVendorInfo() *model.Vendor {
	return &model.Vendor{
		Vendor: g.vendor,
		Host:   g.host,
	}
}

func (g GitHub) config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     g.clientID,
		ClientSecret: g.clientSecretID,
		Endpoint: oauth2.Endpoint{
			TokenURL: "https://github.com/login/oauth/access_token",
		},
	}
}
