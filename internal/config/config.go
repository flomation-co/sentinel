package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type DatabaseConfig struct {
	Hostname           string `json:"hostname"`
	Port               int    `json:"port"`
	Username           string `json:"username"`
	Password           string `json:"password"`
	Database           string `json:"database"`
	EncryptionKey      string `json:"encryption_key"`
	MaxIdleConnections int    `json:"max_idle_connections"`
	MaxOpenConnections int    `json:"max_open_connections"`
	SSLModeOverride    string `json:"ssl_mode"`
}

type CookieConfig struct {
	Domain      string `json:"domain"`
	Secure      bool   `json:"secure"`
	Expiration  int    `json:"expiration"`
	RedirectURL string `json:"redirect_url"`
}

type SecurityConfig struct {
	Salt              string       `json:"salt"`
	Secret            string       `json:"secret"`
	PostRegisterToken bool         `json:"post_register_token"`
	Cookie            CookieConfig `json:"cookie"`
	Realm             string       `json:"realm"`
	LogoutRedirect    *string      `json:"logout_redirect"`
}

type SMTPConfig struct {
	Host     string `json:"host"`
	Username string `json:"username"`
	Password string `json:"password"`
	Port     int64  `json:"port"`
	Secure   bool   `json:"bool"`
}

type NotificationConfig struct {
	Enabled             bool        `json:"enabled"`
	SendFrom            string      `json:"send_from"`
	OverrideDestination *string     `json:"override_destination,omitempty"`
	SMTP                *SMTPConfig `json:"smtp"`
}

type ListenerConfig struct {
	Address string `json:"address"`
	Port    int64  `json:"port"`
	URL     string `json:"url"`
}

func (l *ListenerConfig) ListenAddress() string {
	if l.Address == "" {
		l.Address = "127.0.0.1"
	}

	if l.Port == 0 {
		l.Port = 8999
	}

	return fmt.Sprintf("%v:%v", l.Address, l.Port)
}

type Config struct {
	Listener     *ListenerConfig     `json:"listener"`
	Database     *DatabaseConfig     `json:"database"`
	Security     *SecurityConfig     `json:"security"`
	Notification *NotificationConfig `json:"notification"`
}

func LoadConfig(path string) (*Config, error) {
	root, err := os.OpenRoot(".")
	if err != nil {
		return nil, err
	}

	defer func() {
		_ = root.Close()
	}()

	b, err := root.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(b, &config); err != nil {
		return nil, err
	}

	return &config, nil
}
