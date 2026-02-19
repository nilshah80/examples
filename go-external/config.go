package main

import (
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	ClientID     string
	ClientSecret string
	Subject      string
	Port         int
	SidecarURL   string
}

func LoadConfig() Config {
	_ = godotenv.Load()

	return Config{
		ClientID:     envOrDefault("CLIENT_ID", "external-partner-test"),
		ClientSecret: envOrDefault("CLIENT_SECRET", "external-partner-hmac-secret-key-32chars!"),
		Subject:      envOrDefault("SUBJECT", "hmac-user"),
		Port:         envIntOrDefault("PORT", 3505),
		SidecarURL:   envOrDefault("SIDECAR_URL", "http://localhost:8141"),
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envIntOrDefault(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
