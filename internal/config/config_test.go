package config

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestProductionRejectsDevOutbox(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("JWT_PRIVATE_KEY_PATH", "private.pem")
	t.Setenv("VERIFICATION_HMAC_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	t.Setenv("DEV_OUTBOX_ENABLED", "true")
	t.Setenv("EMAIL_PROVIDER", "dev")
	if _, err := Load(); err == nil {
		t.Fatal("production config accepted the development outbox")
	}
}

func TestDevelopmentDefaults(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("JWT_PRIVATE_KEY_PATH", "private.pem")
	t.Setenv("VERIFICATION_HMAC_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	t.Setenv("DEV_OUTBOX_ENABLED", "")
	t.Setenv("EMAIL_PROVIDER", "dev")
	configuration, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !configuration.DevOutboxEnabled || configuration.CookieSecure {
		t.Fatalf("unexpected development defaults: %+v", configuration)
	}
}

func TestRouteHTTPOptInConfiguration(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("JWT_PRIVATE_KEY_PATH", "private.pem")
	t.Setenv("VERIFICATION_HMAC_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	t.Setenv("EMAIL_PROVIDER", "dev")
	t.Setenv("DEV_OUTBOX_ENABLED", "true")
	for _, value := range []string{"", "false", "true", "typo"} {
		t.Setenv("ALLOW_INSECURE_ROUTE_HTTP", value)
		cfg, err := Load()
		if value == "typo" {
			if err == nil {
				t.Fatal("invalid HTTP flag accepted")
			}
		} else if err != nil || cfg.AllowInsecureRouteHTTP != (value == "true") {
			t.Fatal("incorrect HTTP opt-in", value, err)
		}
	}
}

func TestResendConfiguration(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("JWT_PRIVATE_KEY_PATH", "private.pem")
	t.Setenv("VERIFICATION_HMAC_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	t.Setenv("DEV_OUTBOX_ENABLED", "false")
	t.Setenv("EMAIL_PROVIDER", "resend")
	t.Setenv("RESEND_API_KEY", "re_test_key")
	t.Setenv("RESEND_FROM", "Account Center <verify@example.com>")

	configuration, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if configuration.EmailProvider != "resend" || configuration.ResendAPIKey == "" || configuration.ResendFrom == "" {
		t.Fatalf("resend configuration was not loaded: %+v", configuration)
	}
}

func TestResendRequiresCredentialsAndDisablesOutbox(t *testing.T) {
	t.Setenv("APP_ENV", "development")
	t.Setenv("DATABASE_URL", "postgres://example")
	t.Setenv("JWT_PRIVATE_KEY_PATH", "private.pem")
	t.Setenv("VERIFICATION_HMAC_KEY", base64.StdEncoding.EncodeToString([]byte(strings.Repeat("k", 32))))
	t.Setenv("EMAIL_PROVIDER", "resend")
	t.Setenv("RESEND_API_KEY", "")
	t.Setenv("RESEND_FROM", "")
	t.Setenv("DEV_OUTBOX_ENABLED", "true")

	if _, err := Load(); err == nil {
		t.Fatal("resend configuration accepted missing credentials and enabled outbox")
	}
}
