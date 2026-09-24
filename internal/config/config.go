package config

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/mail"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Environment             string
	HTTPAddr                string
	DatabaseURL             string
	JWTPrivateKeyPath       string
	JWTKeyID                string
	JWTIssuer               string
	AccessTokenTTL          time.Duration
	RefreshTokenTTL         time.Duration
	VerificationTTL         time.Duration
	VerificationHMACKey     []byte
	BcryptCost              int
	CookieSecure            bool
	DevOutboxEnabled        bool
	EmailProvider           string
	ResendAPIKey            string
	ResendFrom              string
	JobPilotAllowedOrigins  []string
	StudyFlowAllowedOrigins []string
}

func Load() (Config, error) {
	configuration := Config{
		Environment:             valueOrDefault("APP_ENV", "development"),
		HTTPAddr:                valueOrDefault("HTTP_ADDR", "127.0.0.1:18082"),
		DatabaseURL:             os.Getenv("DATABASE_URL"),
		JWTPrivateKeyPath:       os.Getenv("JWT_PRIVATE_KEY_PATH"),
		JWTKeyID:                valueOrDefault("JWT_KEY_ID", "dev-key-1"),
		JWTIssuer:               valueOrDefault("JWT_ISSUER", "shared-auth"),
		AccessTokenTTL:          15 * time.Minute,
		RefreshTokenTTL:         7 * 24 * time.Hour,
		VerificationTTL:         10 * time.Minute,
		BcryptCost:              12,
		EmailProvider:           strings.ToLower(valueOrDefault("EMAIL_PROVIDER", "dev")),
		ResendAPIKey:            strings.TrimSpace(os.Getenv("RESEND_API_KEY")),
		ResendFrom:              strings.TrimSpace(os.Getenv("RESEND_FROM")),
		JobPilotAllowedOrigins:  splitList(valueOrDefault("JOBPILOT_ALLOWED_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173")),
		StudyFlowAllowedOrigins: splitList(valueOrDefault("STUDYFLOW_ALLOWED_ORIGINS", "http://127.0.0.1:5174,http://localhost:5174,http://127.0.0.1:8081,http://localhost:8081")),
	}
	var err error
	if configuration.DatabaseURL == "" {
		return Config{}, errors.New("DATABASE_URL is required")
	}
	if configuration.JWTPrivateKeyPath == "" {
		return Config{}, errors.New("JWT_PRIVATE_KEY_PATH is required")
	}
	encodedHMACKey := os.Getenv("VERIFICATION_HMAC_KEY")
	if encodedHMACKey == "" {
		return Config{}, errors.New("VERIFICATION_HMAC_KEY is required")
	}
	configuration.VerificationHMACKey, err = base64.StdEncoding.DecodeString(encodedHMACKey)
	if err != nil || len(configuration.VerificationHMACKey) < 32 {
		return Config{}, errors.New("VERIFICATION_HMAC_KEY must be Base64-encoded and at least 32 bytes")
	}
	configuration.CookieSecure, err = boolValue("COOKIE_SECURE", configuration.Environment == "production")
	if err != nil {
		return Config{}, err
	}
	configuration.DevOutboxEnabled, err = boolValue("DEV_OUTBOX_ENABLED", configuration.Environment == "development")
	if err != nil {
		return Config{}, err
	}
	if configuration.Environment == "production" && configuration.DevOutboxEnabled {
		return Config{}, errors.New("DEV_OUTBOX_ENABLED cannot be true in production")
	}
	switch configuration.EmailProvider {
	case "dev":
		if configuration.Environment == "production" {
			return Config{}, errors.New("EMAIL_PROVIDER=dev cannot be used in production")
		}
		if !configuration.DevOutboxEnabled {
			return Config{}, errors.New("DEV_OUTBOX_ENABLED must be true when EMAIL_PROVIDER=dev")
		}
	case "resend":
		if configuration.ResendAPIKey == "" {
			return Config{}, errors.New("RESEND_API_KEY is required when EMAIL_PROVIDER=resend")
		}
		if configuration.ResendFrom == "" {
			return Config{}, errors.New("RESEND_FROM is required when EMAIL_PROVIDER=resend")
		}
		if _, err := mail.ParseAddress(configuration.ResendFrom); err != nil {
			return Config{}, errors.New("RESEND_FROM must be a valid email address")
		}
		if configuration.DevOutboxEnabled {
			return Config{}, errors.New("DEV_OUTBOX_ENABLED must be false when EMAIL_PROVIDER=resend")
		}
	default:
		return Config{}, errors.New("EMAIL_PROVIDER must be dev or resend")
	}
	if value := os.Getenv("BCRYPT_COST"); value != "" {
		configuration.BcryptCost, err = strconv.Atoi(value)
		if err != nil || configuration.BcryptCost < 4 || configuration.BcryptCost > 31 {
			return Config{}, errors.New("BCRYPT_COST must be between 4 and 31")
		}
	}
	return configuration, nil
}

func valueOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func splitList(value string) []string {
	values := strings.Split(value, ",")
	result := make([]string, 0, len(values))
	for _, item := range values {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func boolValue(key string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", key)
	}
	return parsed, nil
}
