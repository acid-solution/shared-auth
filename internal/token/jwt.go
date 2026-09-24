package token

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var ErrInvalid = errors.New("invalid access token")

type Principal struct {
	UserID    uuid.UUID
	SessionID uuid.UUID
	ClientID  string
}

type Manager struct {
	privateKey *rsa.PrivateKey
	keyID      string
	issuer     string
	ttl        time.Duration
	now        func() time.Time
}

type accessClaims struct {
	SessionID string `json:"sid"`
	jwt.RegisteredClaims
}

func LoadManager(privateKeyPath, keyID, issuer string, ttl time.Duration) (*Manager, error) {
	contents, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, err
	}
	return NewManagerPEM(contents, keyID, issuer, ttl)
}

func NewManagerPEM(contents []byte, keyID, issuer string, ttl time.Duration) (*Manager, error) {
	block, _ := pem.Decode(contents)
	if block == nil {
		return nil, errors.New("private key is not PEM")
	}
	var privateKey *rsa.PrivateKey
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("private key is not RSA")
		}
	} else {
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("cannot parse RSA private key")
		}
	}
	if privateKey.N.BitLen() < 2048 {
		return nil, errors.New("RSA private key must be at least 2048 bits")
	}
	return &Manager{privateKey: privateKey, keyID: keyID, issuer: issuer, ttl: ttl, now: time.Now}, nil
}

func (m *Manager) Sign(userID, sessionID uuid.UUID, audience string) (string, time.Time, error) {
	now := m.now().UTC()
	expiresAt := now.Add(m.ttl)
	claims := accessClaims{
		SessionID: sessionID.String(),
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    m.issuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.NewString(),
		},
	}
	tokenValue := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenValue.Header["kid"] = m.keyID
	signed, err := tokenValue.SignedString(m.privateKey)
	return signed, expiresAt, err
}

func (m *Manager) Parse(raw string) (Principal, error) {
	claims := &accessClaims{}
	parsed, err := jwt.ParseWithClaims(raw, claims, func(tokenValue *jwt.Token) (any, error) {
		if tokenValue.Method != jwt.SigningMethodRS256 || tokenValue.Header["kid"] != m.keyID {
			return nil, ErrInvalid
		}
		return &m.privateKey.PublicKey, nil
	}, jwt.WithIssuer(m.issuer), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || !parsed.Valid || len(claims.Audience) != 1 {
		return Principal{}, ErrInvalid
	}
	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return Principal{}, ErrInvalid
	}
	sessionID, err := uuid.Parse(claims.SessionID)
	if err != nil {
		return Principal{}, ErrInvalid
	}
	return Principal{UserID: userID, SessionID: sessionID, ClientID: claims.Audience[0]}, nil
}

type JWK struct {
	KTY string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	KID string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func (m *Manager) JWKS() JWKS {
	exponent := big.NewInt(int64(m.privateKey.PublicKey.E)).Bytes()
	return JWKS{Keys: []JWK{{
		KTY: "RSA",
		Use: "sig",
		Alg: "RS256",
		KID: m.keyID,
		N:   base64.RawURLEncoding.EncodeToString(m.privateKey.PublicKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(exponent),
	}}}
}
