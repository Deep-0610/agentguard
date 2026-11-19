package config

import (
	"fmt"
	"os"
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
	}
	if c.DatabaseURL == "" { return Config{}, fmt.Errorf("AG_DATABASE_URL is required") }
	if c.ReadTimeout <= 0 || c.WriteTimeout <= 0 || c.IdleTimeout <= 0 || c.ShutdownTimeout <= 0 { return Config{}, fmt.Errorf("HTTP and shutdown timeouts must be positive durations") }
	if len(c.APIKeyPepper) < 32 { return Config{}, fmt.Errorf("AG_API_KEY_PEPPER must contain at least 32 characters") }
	return c, nil
}
func env(key, fallback string) string { if v := os.Getenv(key); v != "" { return v }; return fallback }
func duration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key); if v == "" { return fallback }
	parsed, err := time.ParseDuration(v); if err != nil { return 0 }; return parsed
}
