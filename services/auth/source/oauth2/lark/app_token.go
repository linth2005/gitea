package lark

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"
)

type appAccessTokenReq struct {
	AppID     string `json:"app_id"`     // 自建应用的 app_id
	AppSecret string `json:"app_secret"` // 自建应用的 app_secret
}

type appAccessTokenResp struct {
	Code           int    `json:"code"`             // 错误码
	Msg            string `json:"msg"`              // 错误信息
	AppAccessToken string `json:"app_access_token"` // 用于调用应用级接口的 app_access_token
	Expire         int64  `json:"expire"`           // app_access_token 的过期时间
}

type appAccessToken struct {
	Token     string
	ExpiresAt time.Time
	rMutex    sync.RWMutex

	HTTPClient *http.Client
}

func NewAppAccessToken(client *http.Client) *appAccessToken {
	return &appAccessToken{
		HTTPClient: client,
	}
}

func (a *appAccessToken) getAppAccessToken(clientId, secret string) error {
	// 从本地缓存中获取 app access token
	a.rMutex.RLock()
	if time.Now().Before(a.ExpiresAt) {
		a.rMutex.RUnlock()
		return nil
	}
	a.rMutex.RUnlock()

	reqBody, err := json.Marshal(&appAccessTokenReq{
		AppID:     clientId,
		AppSecret: secret,
	})
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, appAccessTokenURL, bytes.NewBuffer(reqBody))
	if err != nil {
		return fmt.Errorf("failed to create app access token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := a.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send app access token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code while fetching app access token: %d", resp.StatusCode)
	}

	tokenResp := new(appAccessTokenResp)
	if err = json.NewDecoder(resp.Body).Decode(tokenResp); err != nil {
		return fmt.Errorf("failed to decode app access token response: %w", err)
	}

	if tokenResp.Code != 0 {
		return fmt.Errorf("failed to get app access token: code:%v msg: %s", tokenResp.Code, tokenResp.Msg)
	}

	// 更新本地缓存
	expirationDuration := time.Duration(tokenResp.Expire) * time.Second
	a.rMutex.Lock()
	a.Token = tokenResp.AppAccessToken
	a.ExpiresAt = time.Now().Add(expirationDuration)
	a.rMutex.Unlock()

	return nil
}

func (a *appAccessToken) Get(s string) string {
	return a.Token
}

func (a *appAccessToken) setValue(values url.Values) {
	values.Set("app_access_token", a.Token)
}
