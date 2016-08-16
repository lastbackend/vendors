package slack

import (
	"encoding/json"
	"errors"
	"github.com/lastbackend/vendors/model"
	"golang.org/x/oauth2"
	"net/http"
	"net/url"
	"time"
)

type Slack struct {
	clientID       string
	clientSecretID string
	vendor         string
	host           string
}

func GetClient(clientID, clientSecretID, _ string) (*Slack, error) {
	return &Slack{
		clientID:       clientID,
		clientSecretID: clientSecretID,
		vendor:         "slack",
		host:           "slack.com",
	}, nil
}

func (s Slack) GetToken(code string) (*oauth2.Token, error) {

	conf := s.config()

	token, err := conf.Exchange(oauth2.NoContext, code)
	if err != nil {
		return token, err
	}

	return token, nil
}

func (s Slack) RefreshToken(token *oauth2.Token) (*oauth2.Token, bool, error) {

	if token.Expiry.Before(time.Now()) == false || token.RefreshToken == "" {
		return token, false, nil
	}

	restoredToken := &oauth2.Token{
		RefreshToken: token.RefreshToken,
	}

	c := s.config().Client(oauth2.NoContext, restoredToken)

	newToken, err := c.Transport.(*oauth2.Transport).Source.Token()
	if err != nil {
		return newToken, false, err
	}

	return newToken, true, nil
}

func (s Slack) GetUser(token *oauth2.Token) (*model.User, error) {

	payload := struct {
		ID       string `json:"user_id"`
		Username string `json:"user"`
	}{}

	query := make(url.Values)
	query.Set("token", token.AccessToken)

	u := "https://slack.com/api/auth.test?" + query.Encode()
	err := s.httpGet(u, &payload)
	if err != nil {
		return nil, err
	}

	userResponse := struct {
		Profile struct {
			Email string `json:"email"`
		} `json:"profile"`
	}{}

	user := new(model.User)

	query = make(url.Values)
	query.Set("token", token.AccessToken)
	query.Set("user", payload.ID)

	u = "https://slack.com/api/users.profile.get?" + query.Encode()
	if err := s.httpGet(u, &userResponse); err != nil {
		return nil, err
	}

	user.Username = payload.Username
	user.Email = userResponse.Profile.Email
	user.ServiceID = payload.ID

	return user, nil
}

func (s Slack) config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     s.clientID,
		ClientSecret: s.clientSecretID,
		Endpoint: oauth2.Endpoint{
			TokenURL: "https://slack.com/api/oauth.access",
		},
	}
}

func (s Slack) GetVendorInfo() *model.Vendor {
	return &model.Vendor{
		Vendor: s.vendor,
		Host:   s.host,
	}
}

func (s Slack) httpGet(url string, i interface{}) error {

	var e error

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	decoder := json.NewDecoder(resp.Body)
	if resp.StatusCode != 200 {

		if err := decoder.Decode(&e); err != nil {
			return err
		}

		return errors.New(e.Error())
	}

	if err := decoder.Decode(&i); err != nil {
		return err
	}

	return nil
}
