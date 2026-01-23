package config

import (
	"fmt"

	goconfig "github.com/flomation-co/go-config"
)

type DatabaseConfig struct {
	Hostname           string `json:"hostname" env:"DB_HOSTNAME" arg:"db-hostname"`
	Port               int    `json:"port" env:"DB_PORT" arg:"db-port"`
	Username           string `json:"username"  env:"DB_USERNAME" arg:"db-username"`
	Password           string `json:"password" env:"DB_PASSWORD" arg:"db-password"`
	Database           string `json:"database" env:"DB_NAME" arg:"database"`
	EncryptionKey      string `json:"encryption_key" env:"DB_ENCRYPTION_KEY" arg:"db-encryption-key"`
	MaxIdleConnections int    `json:"max_idle_connections" env:"DB_IDLE_CONNS" arg:"db-idle-conns"`
	MaxOpenConnections int    `json:"max_open_connections" env:"DB_OPEN_CONNS" arg:"db-open-conns"`
	SSLModeOverride    string `json:"ssl_mode" env:"DB_SSL_MODE" arg:"db-ssl-mode"`
}

type CookieConfig struct {
	Domain     string `json:"domain" env:"COOKIE_DOMAIN" arg:"cookie-domain"`
	Secure     bool   `json:"secure"`
	Expiration int    `json:"expiration"`
}

type SecurityConfig struct {
	Cookie         CookieConfig `json:"cookie"`
	Realm          string       `json:"realm" env:"AUTH_REALM" arg:"auth-realm"`
	Secret         string       `json:"secret" env:"AUTH_SECRET" arg:"auth-secret"`
	LoginRedirect  *string      `json:"login_redirect" env:"AUTH_LOGIN_REDIRECT" arg:"auth-login-redirect"`
	LogoutRedirect *string      `json:"logout_redirect" env:"AUTH_LOGOUT_REDIRECT" arg:"auth-logout-redirect"`
}

type SMTPConfig struct {
	Host     string `json:"host" env:"SMTP_HOST" arg:"smtp-host"`
	Username string `json:"username" env:"SMTP_USERNAME" arg:"smtp-username"`
	Password string `json:"password" env:"SMTP_PASSWORD" arg:"smtp-password"`
	Port     int64  `json:"port" env:"SMTP_PORT" arg:"smtp-port"`
	Secure   bool   `json:"bool" env:"SMTP_SECURE" arg:"smtp-secure"`
}

type NotificationConfig struct {
	Enabled             bool       `json:"enabled" env:"NOTIFICATIONS_ENABLED" arg:"notifications-enabled"`
	SendFrom            string     `json:"send_from" env:"NOTIFICATIONS_SEND_FROM" arg:"notifications-send-from"`
	OverrideDestination *string    `json:"override_destination,omitempty"`
	SMTP                SMTPConfig `json:"smtp"`
}

type ListenerConfig struct {
	Address string `json:"address" env:"LISTEN_ADDRESS" arg:"listen-address"`
	Port    int64  `json:"port" env:"LISTEN_PORT" arg:"listen-port"`
	URL     string `json:"url" env:"LISTEN_URL" arg:"listen-url"`
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
	Listener     ListenerConfig     `json:"listener"`
	Database     DatabaseConfig     `json:"database"`
	Security     SecurityConfig     `json:"security"`
	Notification NotificationConfig `json:"notification"`
}

func LoadConfig(path string) (*Config, error) {
	// Set up some sensible defaults
	config := Config{
		Security: SecurityConfig{
			Cookie: CookieConfig{
				Domain:     "localhost",
				Secure:     true,
				Expiration: 86400,
			},
			Realm:          "localhost",
			LoginRedirect:  goconfig.String("http://localhost/"),
			LogoutRedirect: goconfig.String("http://localhost/logout"),
		},
		Database: DatabaseConfig{
			MaxIdleConnections: 5,
			MaxOpenConnections: 10,
		},
	}

	err := goconfig.Load(&config, goconfig.String(path))
	if err != nil {
		return nil, err
	}

	return &config, nil
}
