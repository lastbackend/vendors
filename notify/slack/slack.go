package slack

import (
	"golang.org/x/oauth2"
	"net/url"
	"encoding/json"
	"sync"
	"github.com/lastbackend/vendors/interfaces"
	"net/http"
	"errors"
	"time"
)

// const

const (
	API_URL   = "https://slack.com/api"
	TOKEN_URL = "https://slack.com/api/oauth.access"
)

// Model

type Slack struct {
	clientID       string
	clientSecretID string
	vendor         string
	host           string
	access         string
	mode           string
	locker         sync.Mutex
}

func GetClient(clientID, clientSecretID, redirectURI string) *Slack {
	return &Slack{
		clientID:       clientID,
		clientSecretID: clientSecretID,
	}
}

// IVendor

func (Slack) GetVendorInfo() *interfaces.Vendor {

	return &interfaces.Vendor{
		Vendor: "slack",
		Host: "slack.com"}

}

func (Slack) httpGet(url string, i interface{}) error {

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

// IOAuth2

func (s Slack) GetToken(code string) (*oauth2.Token, error) {

	token, err := s.getOAuth2Config().Exchange(oauth2.NoContext, code)
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

	c := s.getOAuth2Config().Client(oauth2.NoContext, restoredToken)

	newToken, err := c.Transport.(*oauth2.Transport).Source.Token()
	if err != nil {
		return newToken, false, err
	}

	return newToken, true, nil
}

func (s Slack) getOAuth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     s.clientID,
		ClientSecret: s.clientSecretID,
		Endpoint: oauth2.Endpoint{
			TokenURL: TOKEN_URL,
		},
	}
}

// INotify

func (Slack) ListChannels(token *oauth2.Token) (*interfaces.NotifyChannels, error) {

	var err error
	var channels = new(interfaces.NotifyChannels)

	payload := struct {
		Ok       bool `json:"ok"`
		Channels []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			IsChannel bool   `json:"is_channel"`
		} `json:"channels"`
	}{}

	client := oauth2.NewClient(oauth2.NoContext, oauth2.StaticTokenSource(token))

	res, err := client.Get(API_URL + "/channels.list?token=" + token.AccessToken)
	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(res.Body).Decode(&payload)
	if err != nil {
		return nil, err
	}

	for _, ch := range payload.Channels {
		channel := interfaces.NotifyChannel{}

		if ch.IsChannel {
			channel.ID = ch.ID
			channel.Name = ch.Name
			channel.Type = "channel"

			*channels = append(*channels, channel)
		}
	}

	return channels, nil
}

func (Slack) ListGroups(token *oauth2.Token) (*interfaces.NotifyGroups, error) {

	var err error
	var groups = new(interfaces.NotifyGroups)

	payload := struct {
		Ok     bool `json:"ok"`
		Groups []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			IsGroup bool   `json:"is_group"`
		} `json:"groups"`
	}{}

	client := oauth2.NewClient(oauth2.NoContext, oauth2.StaticTokenSource(token))

	res, err := client.Get(API_URL + "/groups.list?token=" + token.AccessToken)

	if err != nil {
		return nil, err
	}

	err = json.NewDecoder(res.Body).Decode(&payload)
	if err != nil {
		return nil, err
	}

	for _, gr := range payload.Groups {
		group := interfaces.NotifyGroup{}

		if gr.IsGroup {
			group.ID = gr.ID
			group.Name = gr.Name
			group.Type = "group"

			*groups = append(*groups, group)
		}
	}

	return groups, nil
}

func (s Slack) GetUser(token *oauth2.Token) (*interfaces.User, error) {

	payload := struct {
		ID       string `json:"user_id"`
		Username string `json:"user"`
	}{}

	query := make(url.Values)
	query.Set("token", token.AccessToken)

	u := API_URL + "/auth.test?" + query.Encode()
	err := s.httpGet(u, &payload)
	if err != nil {
		return nil, err
	}

	userResponse := struct {
		Profile struct {
							Email string `json:"email"`
						} `json:"profile"`
	}{}

	user := new(interfaces.User)

	query = make(url.Values)
	query.Set("token", token.AccessToken)
	query.Set("user", payload.ID)

	u = API_URL + "/users.profile.get?" + query.Encode()
	if err := s.httpGet(u, &userResponse); err != nil {
		return nil, err
	}

	user.Username = payload.Username
	user.Email = userResponse.Profile.Email
	user.ServiceID = payload.ID

	return user, nil
}