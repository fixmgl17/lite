package mixed

type ServerConfig struct {
	Username string `json:"username" toml:"username"`
	Password string `json:"password" toml:"password"`
}

type DialerConfig ServerConfig
