package aiauth

import (
	"bytes"
	"io"
	"sync"
	"unsafe"

	jsoniter "github.com/json-iterator/go"
)

const (
	contentType = "application/x-www-form-urlencoded"
	userAgent   = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0"

	csrfUrl        = "https://chatgpt.com/api/auth/csrf"
	promptLoginUrl = "https://chatgpt.com/api/auth/signin/openai?prompt=login&screen_hint=login&ext-oai-did="
	auth0Url       = "https://auth0.openai.com"
	auth0ApiUrl    = "https://auth.openai.com/api/accounts/authorize?"
	authSessionUrl = "https://chatgpt.com/api/auth/session"
)

var (
	Json = jsoniter.ConfigCompatibleWithStandardLibrary
	pool = sync.Pool{
		New: func() interface{} {
			return bytes.NewBuffer(make([]byte, 10240))
		},
	}
)

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
