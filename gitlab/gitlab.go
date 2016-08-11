package gitlab

import (
	"encoding/json"
	"github.com/lastbackend/oauth2/model"
	"golang.org/x/oauth2"
	"strconv"
	"time"
)

type GitLab struct {
	clientID       string
	clientSecretID string
	redirectURI    string
	vendor         string
	host           string
}

func GetClient(clientID, clientSecretID, redirectURI string) (*GitLab, error) {
	return &GitLab{
		clientID:       clientID,
		clientSecretID: clientSecretID,
		redirectURI:    redirectURI,
		vendor:         "gitlab",
		host:           "gitlab.com",
	}, nil
}

func (g GitLab) GetToken(code string) (*oauth2.Token, error) {

	conf := g.config()

	tok, err := conf.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, err
	}

	return tok, nil
}

func (g GitLab) RefreshToken(token *oauth2.Token) (*oauth2.Token, bool, error) {

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

func (g GitLab) GetUser(token *oauth2.Token) (*model.User, error) {

	var err error

	payload := struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		ID       int64  `json:"id"`
	}{}

	user := new(model.User)

	client := oauth2.NewClient(oauth2.NoContext, oauth2.StaticTokenSource(token))

	resUser, err := client.Get("https://gitlab.com/api/v3/user")
	if err != nil {
		return nil, err
	}

	x := []byte{}
	_, err = resUser.Body.Read(x)
	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(resUser.Body).Decode(&payload)
	if err != nil {
		return nil, err
	}

	user.Username = payload.Username
	user.Email = payload.Email
	user.ServiceID = strconv.FormatInt(payload.ID, 10)

	return user, nil
}

func (g GitLab) GetVendorInfo() *model.Vendor {
	return &model.Vendor{
		Vendor: g.vendor,
		Host:   g.host,
	}
}

func (g GitLab) config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     g.clientID,
		ClientSecret: g.clientSecretID,
		RedirectURL:  g.redirectURI,
		Endpoint: oauth2.Endpoint{
			TokenURL: "https://gitlab.com/oauth/token",
		},
	}
}
