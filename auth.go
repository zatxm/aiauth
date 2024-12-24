package aiauth

type Auth interface {
	Proxy(proxyUrl string)
	Go() (string, error)
	Refresh(string) (string, error)
}
