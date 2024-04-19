package lark

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/markbates/goth"
)

type Session struct {
	AuthURL               string
	AccessToken           string
	RefreshToken          string
	ExpiresAt             time.Time
	RefreshTokenExpiresAt time.Time
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
		return "", errors.New("invalid token received from provider")
	}

	s.AccessToken = token.AccessToken
	s.RefreshToken = token.RefreshToken
	s.ExpiresAt = token.Expiry
	refreshExpiresIn := token.Extra("refresh_expires_in").(int64)
	s.RefreshTokenExpiresAt = time.Now().Add(time.Duration(refreshExpiresIn) * time.Second)
	return token.AccessToken, nil
}
