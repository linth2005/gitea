package lark

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

type GrantType string

const (
	authURL         string = "https://open.feishu.cn/open-apis/authen/v1/authorize"                 // 获取授权登录授权码
	tokenURL        string = "https://open.feishu.cn/open-apis/authen/v1/oidc/access_token"         // 获取 user_access_token
	refreshTokenURL string = "https://open.feishu.cn/open-apis/authen/v1/oidc/refresh_access_token" // 刷新 user_access_token
	endpointProfile string = "https://open.feishu.cn/open-apis/authen/v1/user_info"                 // 获取用户信息
)

// Provider is the implementation of `goth.Provider` for accessing Lark
type Provider struct {
	ClientKey    string
	Secret       string
	CallbackURL  string
	HTTPClient   *http.Client
	config       *oauth2.Config
	providerName string
}

func New(clientKey, secret, callbackURL string, scopes ...string) *Provider {
	p := &Provider{
		ClientKey:    clientKey,
		Secret:       secret,
		CallbackURL:  callbackURL,
		providerName: "lark",
	}
	p.config = newConfig(p, authURL, tokenURL, scopes)
	return p
}

func newConfig(provider *Provider, authURL, tokenURL string, scopes []string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     provider.ClientKey,
		ClientSecret: provider.Secret,
		RedirectURL:  provider.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
		Scopes: []string{},
	}

	if len(scopes) > 0 {
		for _, scope := range scopes {
			c.Scopes = append(c.Scopes, scope)
		}
	}
	return c
}

func (p *Provider) Name() string {
	return p.providerName
}

func (p *Provider) SetName(name string) {
	p.providerName = name
}

func (p *Provider) BeginAuth(state string) (goth.Session, error) {
	return &Session{
		AuthURL: p.config.AuthCodeURL(state),
	}, nil
}

func (p *Provider) UnmarshalSession(data string) (goth.Session, error) {
	s := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(s)
	return s, err
}

func (p *Provider) Debug(b bool) {
}

type refreshTokenReq struct {
	GrantType    string `json:"grant_type"`
	RefreshToken string `json:"refresh_token"`
}

func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	apiURL := refreshTokenURL
	body := strings.NewReader(`{"grant_type":"refresh_token","refresh_token":"` + refreshToken + `"}`)

	req, err := http.NewRequest(http.MethodPost, apiURL, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+p.)

	client := p.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send refresh token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code while refreshing token: %d", resp.StatusCode)
	}

	var refreshedToken oauth2.Token
	err = json.NewDecoder(resp.Body).Decode(&refreshedToken)
	if err != nil {
		return nil, fmt.Errorf("failed to decode refreshed token: %w", err)
	}

	return &refreshedToken, nil
}

func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

type larkUser struct {
	OpenID    string `json:"open_id"`
	UnionID   string `json:"union_id"`
	UserID    string `json:"user_id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
	Mobile    string `json:"mobile,omitempty"`
}

// FetchUser will go to Lark and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	sess := session.(*Session)
	user := goth.User{
		AccessToken:  sess.AccessToken,
		Provider:     p.Name(),
		RefreshToken: sess.RefreshToken,
		ExpiresAt:    sess.ExpiresAt,
	}
	if user.AccessToken == "" {
		return user, fmt.Errorf("%s cannot get user information without accessToken", p.providerName)
	}

	req, err := http.NewRequest("GET", endpointProfile, nil)
	if err != nil {
		return user, fmt.Errorf("%s failed to create request: %w", p.providerName, err)
	}
	req.Header.Set("Authorization", "Bearer "+user.AccessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return user, fmt.Errorf("%s failed to get user information: %w", p.providerName, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return user, fmt.Errorf("%s responded with a %d trying to fetch user information", p.providerName, resp.StatusCode)
	}

	var u larkUser
	if err = json.NewDecoder(resp.Body).Decode(&u); err != nil {
		return user, fmt.Errorf("failed to decode user info: %w", err)
	}

	user.UserID = u.UserID
	user.Name = u.Name
	user.Email = u.Email
	user.AvatarURL = u.AvatarURL

	responseBytes, err := io.ReadAll(resp.Body)
	if err = json.Unmarshal(responseBytes, &user.RawData); err != nil {
		return user, err
	}
	return user, nil
}
