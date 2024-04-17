package lark

import (
	"encoding/json"
	"errors"
	"github.com/markbates/goth"
	"time"
)

type Session struct {
	AuthURL      string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

func (s *Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New("lark: missing AuthURL")
	}
	return s.AuthURL, nil
}

func (s *Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s *Session) Authorize(provider goth.Provider, params goth.Params) (string, error) {
	p := provider.(*Provider)
	token, err := p.config.Exchange(goth.ContextForClient(p.Client()), params.Get("code"))
	if err != nil {
		return "", err
	}

	if !token.Valid() {
		return "", errors.New("Invalid token received from provider")
	}

	s.Token = token.AccessToken
	return token.AccessToken, nil
}
