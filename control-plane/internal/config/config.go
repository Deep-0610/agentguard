package config

import (
	"fmt"
	"os"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	DatabaseURL string
	APIKeyPepper string
	Address string
	ReadTimeout time.Duration
	WriteTimeout time.Duration
	IdleTimeout time.Duration
	ShutdownTimeout time.Duration
	Environment string
	OPAURL string
}

func Load() (Config, error) {
	c := Config{
		DatabaseURL: os.Getenv("AG_DATABASE_URL"),
		APIKeyPepper: os.Getenv("AG_API_KEY_PEPPER"),
		Address: env("AG_LISTEN_ADDR", ":8080"),
		ReadTimeout: duration("AG_READ_TIMEOUT", 10*time.Second),
		WriteTimeout: duration("AG_WRITE_TIMEOUT", 30*time.Second),
		IdleTimeout: duration("AG_IDLE_TIMEOUT", 60*time.Second),
		ShutdownTimeout: duration("AG_SHUTDOWN_TIMEOUT", 15*time.Second),
		Environment: strings.ToLower(env("AG_ENV", "development")),
		OPAURL: strings.TrimRight(os.Getenv("AG_OPA_URL"), "/"),
	}
	if c.DatabaseURL == "" { return Config{}, fmt.Errorf("AG_DATABASE_URL is required") }
	if c.ReadTimeout <= 0 || c.WriteTimeout <= 0 || c.IdleTimeout <= 0 || c.ShutdownTimeout <= 0 { return Config{}, fmt.Errorf("HTTP and shutdown timeouts must be positive durations") }
	if len(c.APIKeyPepper) < 32 { return Config{}, fmt.Errorf("AG_API_KEY_PEPPER must contain at least 32 characters") }
	if c.Environment != "development" && c.Environment != "test" && c.Environment != "production" { return Config{}, fmt.Errorf("AG_ENV must be development, test, or production") }
	if c.Environment == "production" {
		dsn, err := url.Parse(c.DatabaseURL)
		if err != nil || (dsn.Scheme != "postgres" && dsn.Scheme != "postgresql") { return Config{}, fmt.Errorf("AG_DATABASE_URL must be a valid PostgreSQL URL") }
		if dsn.Query().Get("sslmode") != "verify-full" { return Config{}, fmt.Errorf("production AG_DATABASE_URL must set sslmode=verify-full") }
		opa, err := url.Parse(c.OPAURL)
		if err != nil || opa.Scheme != "https" || opa.Host == "" { return Config{}, fmt.Errorf("production AG_OPA_URL must use HTTPS") }
	}
	return c, nil
}
func env(key, fallback string) string { if v := os.Getenv(key); v != "" { return v }; return fallback }
func duration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key); if v == "" { return fallback }
	parsed, err := time.ParseDuration(v); if err != nil { return 0 }; return parsed
}
