package aiauth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"sync"
	"unsafe"

	jsoniter "github.com/json-iterator/go"
)

const (
	contentType     = "application/x-www-form-urlencoded"
	contentTypeJson = "application/json"
	userAgent       = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"

	csrfUrl                 = "https://chatgpt.com/api/auth/csrf"
	promptLoginUrl          = "https://chatgpt.com/api/auth/signin/openai?prompt=login&screen_hint=login&ext-oai-did="
	auth0Url                = "https://auth0.openai.com"
	authAccountAuthorizeUrl = "https://auth.openai.com/api/accounts/authorize?"
	chatTokenUrl            = "https://chatgpt.com/api/auth/session"
	oauthTokenUrl           = "https://auth.openai.com/api/accounts/oauth/token"
	platformRedirectUri     = "https://platform.openai.com/auth/callback"
	auth0Client             = "eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjEuMCJ9"
	clientId                = "app_2SKx67EdpoN0G6j64rFvigXD"

	charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._~-"
)

var (
	Json = jsoniter.ConfigCompatibleWithStandardLibrary
	pool = sync.Pool{
		New: func() interface{} {
			return bytes.NewBuffer(make([]byte, 10240))
		},
	}
)

// 读取http通信返回结果
func readAllToString(r io.Reader) (string, error) {
	buffer := pool.Get().(*bytes.Buffer)
	buffer.Reset()
	_, err := io.Copy(buffer, r)
	if err != nil {
		pool.Put(buffer)
		return "", err
	}
	pool.Put(buffer)
	temp := buffer.Bytes()
	length := len(temp)
	var body []byte
	if cap(temp) > (length + length/10) {
		body = make([]byte, length)
		copy(body, temp)
	} else {
		body = temp
	}
	return *(*string)(unsafe.Pointer(&body)), nil
}

// 生成一个随机的字符串
func generateRandomString(length int) string {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return ""
	}

	// 将随机字节转换为字符集内的字符串
	var result []byte
	for i := 0; i < length; i++ {
		result = append(result, charset[int(bytes[i])%len(charset)])
	}
	return *(*string)(unsafe.Pointer(&result))
}

// 生成随机字符串的base64
func generateRandomBase64String(length int) string {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return ""
	}
	return base64.URLEncoding.EncodeToString(bytes)
}

// 字符串sha256
func generateCodeChallenge(codeVerifier string) string {
	hash := sha256.New()
	hash.Write([]byte(codeVerifier))
	hashBytes := hash.Sum(nil)
	return base64.RawURLEncoding.EncodeToString(hashBytes)
}
