package web

type ServerOptions struct {
	Port            int
	DBPath          string
	SessionsEncKey  string
	SessionsHashKey string
}
