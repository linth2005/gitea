package lark

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/markbates/goth"
	"golang.org/x/oauth2"
)

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
	} else {
		c.Scopes = append(c.Scopes, "profile", "email")
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

func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
}

func (p *Provider) RefreshTokenAvailable() bool {
	return true
}

// FetchUser will go to Lark and access basic information about the user.
func (p *Provider) FetchUser(session goth.Session) (goth.User, error) {
	// TODO implement me
	panic("implement me")
}
