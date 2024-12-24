package aiauth

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	mreq "github.com/imroc/req/v3"
)

// chat登录
type chatAuth struct {
	email    string
	password string
	uuid     string
	client   *mreq.Client
}

type csrfTokenResponse struct {
	Token string `json:"csrfToken"`
}

func NewChat(email, password, proxyUrl string) Auth {
	client := mreq.C().SetUserAgent(userAgent).ImpersonateChrome()
	if proxyUrl != "" {
		client.SetProxyURL(proxyUrl)
	}
	return &chatAuth{
		email:    email,
		password: password,
		uuid:     uuid.NewString(),
		client:   client}
}

func (a *chatAuth) Proxy(proxyUrl string) {
	a.client.SetProxyURL(proxyUrl)
}

// 登录获取token
func (a *chatAuth) Go() (string, error) {
	// 获取csrf token
	resp, err := a.client.R().
		SetHeader("content-type", contentTypeJson).
		Get("https://chatgpt.com/api/auth/csrf")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("Get CSRF token http status error")
	}
	var csrf csrfTokenResponse
	err = Json.NewDecoder(resp.Body).Decode(&csrf)
	if err != nil {
		return "", nil
	}

	// 获取authorize_url
	form := url.Values{
		"callbackUrl": {"/"},
		"csrfToken":   {csrf.Token},
		"json":        {"true"},
	}
	goPromptLoginUrl := promptLoginUrl + a.uuid + "&ext-login-allow-phone=true&country_code=US"
	resp, err = a.client.R().
		SetHeader("content-type", contentType).
		SetBody(form.Encode()).
		Post(goPromptLoginUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("Get authorized url http status error")
	}
	authorize := map[string]string{}
	err = Json.NewDecoder(resp.Body).Decode(&authorize)
	if err != nil {
		return "", nil
	}
	authorizedUrl := authorize["url"]

	// 获取验证n个重定向
	goAuthorizedUrl := authorizedUrl + "&device_id=" + a.uuid
	a.client.SetRedirectPolicy(mreq.NoRedirectPolicy())
	resp, err = a.client.R().
		SetHeader("referer", "https://chatgpt.com/").
		Get(goAuthorizedUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		return "", errors.New("request login url status error")
	}
	aUrl := resp.Header.Get("Location")
	resp, err = a.client.R().
		SetHeader("referer", "https://chatgpt.com/").
		Get(aUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		return "", errors.New("request login url status error 2")
	}
	bUrl := resp.Header.Get("Location")
	resp, err = a.client.R().
		SetHeader("referer", "https://chatgpt.com/").
		Get(bUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		return "", errors.New("request login url status error 3")
	}
	cUrl := resp.Header.Get("Location")
	resp, err = a.client.R().
		SetHeader("referer", "https://chatgpt.com/").
		Get(cUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errors.New("request login url status error 4")
	}

	// 验证用户登录并获取state
	au, _ := url.Parse(cUrl)
	query := au.Query()
	query.Set("max_age", "0")
	query.Set("ext-login-hint-email", a.email)
	query.Set("login_hint", a.email)
	query.Set("idp", "auth0")
	query.Set("connection", "Username-Password-Authentication")
	query.Set("ext-oai-did-source", "web")
	checkUrl := authAccountAuthorizeUrl + query.Encode()
	resp, err = a.client.R().
		SetHeader("referer", cUrl).
		Get(checkUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		return "", errors.New("request login check email error")
	}
	checkAUrl := resp.Header.Get("Location")
	resp, err = a.client.R().
		SetHeader("referer", "https://auth.openai.com/").
		Get(checkAUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		return "", errors.New("request login check email error 1")
	}
	passUrl := auth0Url + resp.Header.Get("Location")
	resp, err = a.client.R().
		SetHeader("referer", "https://auth.openai.com/").
		Get(passUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errors.New("request login check email error 2")
	}
	lu, _ := url.Parse(passUrl)
	state := lu.Query().Get("state")

	// 验证用户、密码
	checkForm := url.Values{
		"state":    {state},
		"username": {a.email},
		"password": {a.password},
	}
	resp, err = a.client.R().
		SetHeader("content-type", contentType).
		SetHeader("referer", passUrl).
		SetBody(checkForm.Encode()).
		Post(passUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		return "", errors.New("request login check password error")
	}

	/*****登录返回验证start*****/
	// https://auth0.openai.com/authorize/resume?state=nZ1qTbSikSX8Dws--L7FoO4cljBw_NYP
	resumeUrl := auth0Url + resp.Header.Get("Location")
	resp, err = a.client.R().
		SetHeader("referer", passUrl).
		Get(resumeUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		return "", errors.New("request login callback check resume error")
	}
	// https://auth.openai.com/api/accounts/callback/auth0?code=eZ2pqiMgJjJHLIFQCQkF05EQ7qwZ7VBmurBr_Q0BC_t4O&state=9ffdf316-2b81-4081-a42d-259073ac072e
	callbackUrl := resp.Header.Get("Location")
	resp, err = a.client.R().Get(callbackUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 307 {
		return "", errors.New("request login callback check account callback error")
	}
	// https://auth.openai.com/api/oauth/oauth2/auth?audience=...
	oauthUrl := resp.Header.Get("Location")
	resp, err = a.client.R().Get(oauthUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		return "", errors.New("request login callback check oauth error")
	}
	// https://auth.openai.com/api/accounts/consent?consent_challenge=...
	consentUrl := resp.Header.Get("Location")
	resp, err = a.client.R().Get(consentUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		return "", errors.New("request login callback check consent error")
	}
	// https://auth.openai.com/api/oauth/oauth2/auth?audience=...
	oauthUrl = resp.Header.Get("Location")
	resp, err = a.client.R().Get(oauthUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 303 {
		return "", errors.New("request login callback check oauth2 error")
	}
	// https://chatgpt.com/api/auth/callback/openai?code=...
	chatCallbackUrl := resp.Header.Get("Location")
	resp, err = a.client.R().Get(chatCallbackUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		return "", errors.New("request login callback check last back error")
	}
	// https://chatgpt.com/
	chatUrl := resp.Header.Get("Location")
	resp, err = a.client.R().Get(chatUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errors.New("request login callback check chat web error")
	}
	/*****登录返回验证end*****/

	// 获取token
	resp, err = a.client.R().Get(chatTokenUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errors.New("request access token error")
	}
	b, err := readAllToString(resp.Body)
	if err != nil {
		return "", err
	}

	return b, nil
}

// 刷新token
func (a *chatAuth) Refresh(refreshToken string) (string, error) {
	return "", errors.New("no supported")
}
