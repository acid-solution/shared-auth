package identity

import (
	"net/mail"
	"strings"

	"github.com/LeoninCS/shared-auth/internal/domain"
)

func NormalizeEmail(value string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if len(normalized) < 3 || len(normalized) > 254 {
		return "", domain.ErrInvalidInput
	}
	address, err := mail.ParseAddress(normalized)
	if err != nil || address.Address != normalized || strings.ContainsAny(normalized, "\r\n") {
		return "", domain.ErrInvalidInput
	}
	return normalized, nil
}
