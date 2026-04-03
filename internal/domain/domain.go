package domain

import "time"

type Device struct {
	ID                string    `json:"device_id"`
	AuthPublicKey     string    `json:"auth_public_key"`
	ExchangePublicKey string    `json:"exchange_public_key"`
	CreatedAt         time.Time `json:"created_at"`
	LastSeenAt        time.Time `json:"last_seen_at"`
	Status            string    `json:"status"`
}

type Message struct {
	ID                string    `json:"message_id"`
	SenderDeviceID    string    `json:"sender_device_id"`
	RecipientDeviceID string    `json:"recipient_device_id"`
	Ciphertext        string    `json:"ciphertext"`
	Nonce             string    `json:"nonce"`
	MessageType       string    `json:"message_type"`
	AttachmentID      *string   `json:"attachment_id,omitempty"`
	IdempotencyKey    string    `json:"-"`
	CreatedAt         time.Time `json:"created_at"`
	ExpiresAt         time.Time `json:"expires_at"`
}

type Attachment struct {
	ID             string    `json:"attachment_id"`
	DeviceID       string    `json:"device_id"`
	ObjectKey      string    `json:"object_key"`
	CiphertextSize int64     `json:"ciphertext_size"`
	MIMEType       string    `json:"mime_type"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type AuthChallenge struct {
	ID        string
	DeviceID  string
	Nonce     string
	ExpiresAt time.Time
	CreatedAt time.Time
}

type SessionClaims struct {
	DeviceID string
}
