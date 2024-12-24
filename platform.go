package aiauth

import (
	"errors"
	"net/url"

	"github.com/google/uuid"
	mreq "github.com/imroc/req/v3"
)

// platform平台登录
type platformAuth struct {
	email    string
	password string
	uuid     string
	client   *mreq.Client
}

func NewPlatform(email, password, proxyUrl string) Auth {
	client := mreq.C().SetUserAgent(userAgent).ImpersonateChrome()
	if proxyUrl != "" {
		client.SetProxyURL(proxyUrl)
	}
	return &platformAuth{
		email:    email,
		password: password,
		uuid:     uuid.NewString(),
		client:   client}
}

func (a *platformAuth) Proxy(proxyUrl string) {
	a.client.SetProxyURL(proxyUrl)
}

func (a *platformAuth) Go() (string, error) {
	a.client.SetRedirectPolicy(mreq.NoRedirectPolicy())

	/*****点击登录验证*****/
	// https://auth.openai.com/api/accounts/authorize?issuer=...
	state := generateRandomBase64String(43)
	nonce := generateRandomBase64String(43)
	codeVerifier := generateRandomString(43)
	codeChallenge := generateCodeChallenge(codeVerifier)
	authorizeVals := url.Values{
		"issuer":                {"https://auth.openai.com"},
		"client_id":             {clientId},
		"audience":              {"https://api.openai.com/v1"},
		"redirect_uri":          {platformRedirectUri},
		"device_id":             {a.uuid},
		"max_age":               {"0"},
		"scope":                 {"openid profile email offline_access"},
		"response_type":         {"code"},
		"response_mode":         {"query"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"auth0Client":           {auth0Client}}
	authorizeUrl := authAccountAuthorizeUrl + authorizeVals.Encode()
	resp, err := a.client.R().
		SetHeader("referer", "https://platform.openai.com/").
		Get(authorizeUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		return "", errors.New("request account authorize http status error")
	}
	// https://auth.openai.com/api/oauth/oauth2/auth?audience=...
	authUrl := resp.Header.Get("Location")
	resp, err = a.client.R().
		SetHeader("referer", "https://platform.openai.com/").
		Get(authUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		return "", errors.New("request api oauth http status error")
	}
	// https://auth.openai.com/api/accounts/login?login_challenge=...
	loginUrl := resp.Header.Get("Location")
	resp, err = a.client.R().
		SetHeader("referer", "https://platform.openai.com/").
		Get(loginUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		return "", errors.New("request login http status error")
	}
	// https://auth.openai.com/authorize?audience=...
	aAuthorizeUrl := resp.Header.Get("Location")
	resp, err = a.client.R().
		SetHeader("referer", "https://platform.openai.com/").
		Get(aAuthorizeUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errors.New("request authorize http status error")
	}

	// 验证用户名
	// https://auth.openai.com/api/accounts/authorize?audience=...
	au, _ := url.Parse(aAuthorizeUrl)
	query := au.Query()
	query.Set("ext-login-hint-email", a.email)
	query.Set("login_hint", a.email)
	query.Set("idp", "auth0")
	query.Set("ext-oai-did", a.uuid)
	query.Set("ext-oai-did-source", "web")
	checkUrl := authAccountAuthorizeUrl + query.Encode()
	resp, err = a.client.R().
		SetHeader("referer", aAuthorizeUrl).
		Get(checkUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		return "", errors.New("request login check email error")
	}
	// https://auth0.openai.com/authorize?response_type=...
	auth0orizeUrl := resp.Header.Get("Location")
	resp, err = a.client.R().
		SetHeader("referer", "https://auth.openai.com/").
		Get(auth0orizeUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 302 {
		return "", errors.New("request check email back http status error")
	}
	// https://auth0.openai.com/u/login/password?state=...
	passwdUrl := auth0Url + resp.Header.Get("Location")
	resp, err = a.client.R().
		SetHeader("referer", "https://auth.openai.com/").
		Get(passwdUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errors.New("request login back password http status error")
	}

	// 验证用户、密码
	lu, _ := url.Parse(passwdUrl)
	stateParam := lu.Query().Get("state")
	checkForm := url.Values{
		"state":    {stateParam},
		"username": {a.email},
		"password": {a.password},
	}
	resp, err = a.client.R().
		SetHeader("content-type", contentType).
		SetHeader("referer", passwdUrl).
		SetBody(checkForm.Encode()).
		Post(passwdUrl)
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
		SetHeader("referer", passwdUrl).
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
	// https://platform.openai.com/auth/callback?code=...
	platformCallbackUrl := resp.Header.Get("Location")
	resp, err = a.client.R().Get(platformCallbackUrl)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errors.New("request login callback check last back error")
	}
	/*****登录返回验证end*****/

	// 获取token
	pb, _ := url.Parse(platformCallbackUrl)
	codeBack := pb.Query().Get("code")
	jsonBody, _ := Json.Marshal(map[string]string{
		"client_id":     clientId,
		"code":          codeBack,
		"code_verifier": codeVerifier,
		"grant_type":    "authorization_code",
		"redirect_uri":  platformRedirectUri,
	})
	resp, err = a.client.R().
		SetHeader("auth0-client", auth0Client).
		SetHeader("content-type", contentTypeJson).
		SetHeader("origin", "https://platform.openai.com").
		SetHeader("referer", "https://platform.openai.com/").
		SetBodyBytes(jsonBody).
		Post(oauthTokenUrl)
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
