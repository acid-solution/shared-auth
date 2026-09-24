package verification

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
)

var ErrProviderNotConfigured = errors.New("verification delivery provider is not configured")

type Delivery struct {
	ChallengeID uuid.UUID `json:"challenge_id"`
	ClientID    string    `json:"client_id"`
	Identifier  string    `json:"identifier"`
	Purpose     string    `json:"purpose"`
	Code        string    `json:"code"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
}

type Sender interface {
	Send(context.Context, Delivery) error
}

type UnavailableSender struct{}

func (UnavailableSender) Send(context.Context, Delivery) error {
	return ErrProviderNotConfigured
}

type DevOutbox struct {
	mu       sync.RWMutex
	messages []Delivery
}

func NewDevOutbox() *DevOutbox {
	return &DevOutbox{}
}

func (o *DevOutbox) Send(_ context.Context, delivery Delivery) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.messages = append(o.messages, delivery)
	return nil
}

func (o *DevOutbox) List(identifier string) []Delivery {
	o.mu.RLock()
	defer o.mu.RUnlock()
	result := make([]Delivery, 0, len(o.messages))
	for _, message := range o.messages {
		if identifier == "" || message.Identifier == identifier {
			result = append(result, message)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.After(result[j].CreatedAt) })
	return result
}
