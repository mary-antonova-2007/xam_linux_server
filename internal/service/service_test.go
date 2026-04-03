package service

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/url"
	"os"
	"testing"
	"time"

	"xam/linux_server/internal/auth"
	"xam/linux_server/internal/config"
	"xam/linux_server/internal/domain"
	"xam/linux_server/internal/storage"
)

type memoryStore struct {
	devices     map[string]domain.Device
	authIndex   map[string]string
	challenges  map[string]domain.AuthChallenge
	attachments map[string]domain.Attachment
	messages    map[string]domain.Message
}

func newMemoryStore() *memoryStore {
	return &memoryStore{
		devices:     make(map[string]domain.Device),
		authIndex:   make(map[string]string),
		challenges:  make(map[string]domain.AuthChallenge),
		attachments: make(map[string]domain.Attachment),
		messages:    make(map[string]domain.Message),
	}
}

func (m *memoryStore) Ping(ctx context.Context) error                                   { return nil }
func (m *memoryStore) Close() error                                                     { return nil }
func (m *memoryStore) Health(ctx context.Context) error                                 { return nil }
func (m *memoryStore) DeleteExpiredChallenges(ctx context.Context, now time.Time) error { return nil }
func (m *memoryStore) DeleteExpiredMessages(ctx context.Context, now time.Time) error   { return nil }
func (m *memoryStore) ListExpiredAttachments(ctx context.Context, now time.Time) ([]domain.Attachment, error) {
	return nil, nil
}
func (m *memoryStore) DeleteAttachment(ctx context.Context, attachmentID string) error { return nil }

func (m *memoryStore) CreateDevice(ctx context.Context, authKey, exchangeKey string, now time.Time) (domain.Device, error) {
	device := domain.Device{
		ID:                "device-" + authKey[:8],
		AuthPublicKey:     authKey,
		ExchangePublicKey: exchangeKey,
		CreatedAt:         now,
		LastSeenAt:        now,
		Status:            "active",
	}
	m.devices[device.ID] = device
	m.authIndex[authKey] = device.ID
	return device, nil
}

func (m *memoryStore) GetDeviceByID(ctx context.Context, deviceID string) (domain.Device, error) {
	device, ok := m.devices[deviceID]
	if !ok {
		return domain.Device{}, storage.ErrNotFound
	}
	return device, nil
}

func (m *memoryStore) GetDeviceByAuthKey(ctx context.Context, authKey string) (domain.Device, error) {
	deviceID, ok := m.authIndex[authKey]
	if !ok {
		return domain.Device{}, storage.ErrNotFound
	}
	return m.devices[deviceID], nil
}

func (m *memoryStore) TouchDevice(ctx context.Context, deviceID string, now time.Time) error {
	device, ok := m.devices[deviceID]
	if !ok {
		return storage.ErrNotFound
	}
	device.LastSeenAt = now
	m.devices[deviceID] = device
	return nil
}

func (m *memoryStore) CreateChallenge(ctx context.Context, challenge domain.AuthChallenge) error {
	m.challenges[challenge.ID] = challenge
	return nil
}

func (m *memoryStore) GetChallenge(ctx context.Context, challengeID string) (domain.AuthChallenge, error) {
	challenge, ok := m.challenges[challengeID]
	if !ok {
		return domain.AuthChallenge{}, storage.ErrNotFound
	}
	return challenge, nil
}

func (m *memoryStore) DeleteChallenge(ctx context.Context, challengeID string) error {
	delete(m.challenges, challengeID)
	return nil
}

func (m *memoryStore) CreateAttachment(ctx context.Context, attachment domain.Attachment) (domain.Attachment, error) {
	m.attachments[attachment.ID] = attachment
	return attachment, nil
}

func (m *memoryStore) GetAttachment(ctx context.Context, attachmentID string) (domain.Attachment, error) {
	attachment, ok := m.attachments[attachmentID]
	if !ok {
		return domain.Attachment{}, storage.ErrNotFound
	}
	return attachment, nil
}

func (m *memoryStore) CanAccessAttachment(ctx context.Context, attachmentID, deviceID string) (bool, error) {
	attachment, ok := m.attachments[attachmentID]
	if !ok {
		return false, storage.ErrNotFound
	}
	if attachment.DeviceID == deviceID {
		return true, nil
	}
	for _, message := range m.messages {
		if message.AttachmentID != nil && *message.AttachmentID == attachmentID &&
			(message.SenderDeviceID == deviceID || message.RecipientDeviceID == deviceID) {
			return true, nil
		}
	}
	return false, nil
}

func (m *memoryStore) CreateMessage(ctx context.Context, message domain.Message) (domain.Message, error) {
	for _, current := range m.messages {
		if current.SenderDeviceID == message.SenderDeviceID && current.IdempotencyKey == message.IdempotencyKey {
			return current, nil
		}
	}
	m.messages[message.ID] = message
	return message, nil
}

func (m *memoryStore) PullMessages(ctx context.Context, recipientDeviceID string, limit int, now time.Time) ([]domain.Message, error) {
	var messages []domain.Message
	for _, message := range m.messages {
		if message.RecipientDeviceID == recipientDeviceID && message.ExpiresAt.After(now) {
			messages = append(messages, message)
		}
	}
	if len(messages) > limit {
		messages = messages[:limit]
	}
	return messages, nil
}

func (m *memoryStore) AckDeleteMessages(ctx context.Context, recipientDeviceID string, messageIDs []string) (int64, error) {
	var deleted int64
	for _, id := range messageIDs {
		message, ok := m.messages[id]
		if ok && message.RecipientDeviceID == recipientDeviceID {
			delete(m.messages, id)
			deleted++
		}
	}
	return deleted, nil
}

type fakeObjectStore struct{}

func (f *fakeObjectStore) EnsureBucket(ctx context.Context) error                   { return nil }
func (f *fakeObjectStore) RemoveObject(ctx context.Context, objectKey string) error { return nil }
func (f *fakeObjectStore) Health(ctx context.Context) error                         { return nil }
func (f *fakeObjectStore) PresignedPut(ctx context.Context, objectKey string, mimeType string) (*url.URL, error) {
	return url.Parse("https://example.invalid/upload/" + objectKey)
}
func (f *fakeObjectStore) PresignedGet(ctx context.Context, objectKey string) (*url.URL, error) {
	return url.Parse("https://example.invalid/download/" + objectKey)
}

func newTestService(t *testing.T) (*Service, ed25519.PrivateKey, domain.Device) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authKey := base64.StdEncoding.EncodeToString(pub)
	exchangeKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	store := newMemoryStore()
	cfg := config.Config{
		TokenTTL:           time.Hour,
		ChallengeTTL:       5 * time.Minute,
		MessageTTL:         24 * time.Hour,
		PullLimitDefault:   50,
		PullLimitMax:       200,
		MaxCiphertextBytes: 1024 * 1024,
		MaxAttachmentBytes: 10 * 1024 * 1024,
		MaxACKItems:        100,
	}
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	tokens := auth.NewTokenManager("test-secret", cfg.TokenTTL)
	svc := New(cfg, store, &fakeObjectStore{}, tokens, logger)
	device, err := svc.RegisterDevice(context.Background(), RegisterDeviceInput{
		AuthPublicKey:     authKey,
		ExchangePublicKey: exchangeKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc, priv, device
}

func TestVerifyChallenge(t *testing.T) {
	svc, priv, device := newTestService(t)
	challenge, err := svc.CreateChallenge(context.Background(), CreateChallengeInput{AuthPublicKey: device.AuthPublicKey})
	if err != nil {
		t.Fatal(err)
	}
	rawNonce, err := base64.StdEncoding.DecodeString(challenge.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(priv, rawNonce)
	token, _, returnedDeviceID, err := svc.VerifyChallenge(context.Background(), VerifyChallengeInput{
		ChallengeID:     challenge.ID,
		SignatureBase64: base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("expected access token")
	}
	if returnedDeviceID != device.ID {
		t.Fatalf("expected %s, got %s", device.ID, returnedDeviceID)
	}
}

func TestMessageLifecycleAndIdempotency(t *testing.T) {
	svc, _, sender := newTestService(t)
	recipient, err := svc.RegisterDevice(context.Background(), RegisterDeviceInput{
		AuthPublicKey:     base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)),
		ExchangePublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32)),
	})
	if err != nil {
		t.Fatal(err)
	}
	input := SendMessageInput{
		RecipientDeviceID: recipient.ID,
		Ciphertext:        base64.StdEncoding.EncodeToString([]byte("ciphertext")),
		Nonce:             base64.StdEncoding.EncodeToString([]byte("nonce")),
		MessageType:       "text",
		IdempotencyKey:    "idem-1",
	}
	first, err := svc.SendMessage(context.Background(), sender.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.SendMessage(context.Background(), sender.ID, input)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID {
		t.Fatalf("expected idempotent create, got %s and %s", first.ID, second.ID)
	}
	messages, err := svc.PullMessages(context.Background(), recipient.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 {
		t.Fatalf("expected 1 message, got %d", len(messages))
	}
	deleted, err := svc.AckDeleteMessages(context.Background(), recipient.ID, []string{first.ID})
	if err != nil {
		t.Fatal(err)
	}
	if deleted != 1 {
		t.Fatalf("expected 1 deleted, got %d", deleted)
	}
	messages, err = svc.PullMessages(context.Background(), recipient.ID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 0 {
		t.Fatalf("expected 0 messages after ack, got %d", len(messages))
	}
}
