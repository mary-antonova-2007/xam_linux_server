package service

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"xam/linux_server/internal/auth"
	"xam/linux_server/internal/config"
	"xam/linux_server/internal/debuglog"
	"xam/linux_server/internal/domain"
	"xam/linux_server/internal/push"
	"xam/linux_server/internal/storage"
)

var (
	ErrUnauthorized    = errors.New("unauthorized")
	ErrInvalidInput    = errors.New("invalid input")
	ErrRateLimited     = errors.New("rate limited")
	ErrAttachmentOwner = errors.New("attachment does not belong to sender")
)

type Store interface {
	Ping(ctx context.Context) error
	Close() error
	CreateDevice(ctx context.Context, authKey, exchangeKey string, now time.Time) (domain.Device, error)
	GetDeviceByID(ctx context.Context, deviceID string) (domain.Device, error)
	GetDeviceByAuthKey(ctx context.Context, authKey string) (domain.Device, error)
	TouchDevice(ctx context.Context, deviceID string, now time.Time) error
	CreateChallenge(ctx context.Context, challenge domain.AuthChallenge) error
	GetChallenge(ctx context.Context, challengeID string) (domain.AuthChallenge, error)
	DeleteChallenge(ctx context.Context, challengeID string) error
	CreateAttachment(ctx context.Context, attachment domain.Attachment) (domain.Attachment, error)
	GetAttachment(ctx context.Context, attachmentID string) (domain.Attachment, error)
	CanAccessAttachment(ctx context.Context, attachmentID, deviceID string) (bool, error)
	CreateMessage(ctx context.Context, message domain.Message) (domain.Message, error)
	PullMessages(ctx context.Context, recipientDeviceID string, limit int, now time.Time) ([]domain.Message, error)
	AckDeleteMessages(ctx context.Context, recipientDeviceID string, messageIDs []string) (int64, error)
	DeleteExpiredChallenges(ctx context.Context, now time.Time) error
	DeleteExpiredMessages(ctx context.Context, now time.Time) error
	ListExpiredAttachments(ctx context.Context, now time.Time) ([]domain.Attachment, error)
	DeleteAttachment(ctx context.Context, attachmentID string) error
	Health(ctx context.Context) error
	UpdateDevicePushToken(ctx context.Context, deviceID, pushToken string, updatedAt time.Time) error
}

type ObjectStore interface {
	EnsureBucket(ctx context.Context) error
	PresignedPut(ctx context.Context, objectKey string, mimeType string) (*url.URL, error)
	PresignedGet(ctx context.Context, objectKey string) (*url.URL, error)
	PutObject(ctx context.Context, objectKey string, reader io.Reader, size int64, mimeType string) error
	GetObject(ctx context.Context, objectKey string) (io.ReadCloser, error)
	RemoveObject(ctx context.Context, objectKey string) error
	Health(ctx context.Context) error
}

type Clock func() time.Time

type Service struct {
	cfg     config.Config
	store   Store
	objects ObjectStore
	tokens  *auth.TokenManager
	push    push.Sender
	logger  *slog.Logger
	logbook *debuglog.LogBook
	now     Clock
}

type RegisterDeviceInput struct {
	AuthPublicKey     string `json:"auth_public_key"`
	ExchangePublicKey string `json:"exchange_public_key"`
}

type CreateChallengeInput struct {
	AuthPublicKey string `json:"auth_public_key"`
}

type VerifyChallengeInput struct {
	ChallengeID     string `json:"challenge_id"`
	SignatureBase64 string `json:"signature"`
}

type SendMessageInput struct {
	RecipientDeviceID string  `json:"recipient_device_id"`
	Ciphertext        string  `json:"ciphertext"`
	Nonce             string  `json:"nonce"`
	MessageType       string  `json:"message_type"`
	AttachmentID      *string `json:"attachment_id,omitempty"`
	IdempotencyKey    string
}

type UploadInitInput struct {
	CiphertextSize int64  `json:"ciphertext_size"`
	MIMEType       string `json:"mime_type"`
}

type UpdatePushTokenInput struct {
	PushToken string `json:"push_token"`
}

func New(cfg config.Config, store Store, objects ObjectStore, tokens *auth.TokenManager, pushSender push.Sender, logger *slog.Logger, logbook *debuglog.LogBook) *Service {
	if pushSender == nil {
		pushSender = push.NoopSender{}
	}
	return &Service{
		cfg:     cfg,
		store:   store,
		objects: objects,
		tokens:  tokens,
		push:    pushSender,
		logger:  logger,
		logbook: logbook,
		now:     time.Now,
	}
}

func (s *Service) RegisterDevice(ctx context.Context, input RegisterDeviceInput) (domain.Device, error) {
	if err := validateBase64Key(input.AuthPublicKey); err != nil {
		return domain.Device{}, fmt.Errorf("%w: invalid auth public key", ErrInvalidInput)
	}
	if err := validateBase64Key(input.ExchangePublicKey); err != nil {
		return domain.Device{}, fmt.Errorf("%w: invalid exchange public key", ErrInvalidInput)
	}

	device, err := s.store.CreateDevice(ctx, input.AuthPublicKey, input.ExchangePublicKey, s.now().UTC())
	if err != nil {
		return domain.Device{}, err
	}
	s.logEvent(slog.LevelInfo, "device registered", map[string]any{
		"device_id":           device.ID,
		"auth_public_key_len": len(input.AuthPublicKey),
		"exchange_public_len": len(input.ExchangePublicKey),
	})
	return device, nil
}

func (s *Service) CreateChallenge(ctx context.Context, input CreateChallengeInput) (domain.AuthChallenge, error) {
	device, err := s.store.GetDeviceByAuthKey(ctx, input.AuthPublicKey)
	if err != nil {
		return domain.AuthChallenge{}, err
	}

	rawNonce := make([]byte, 32)
	if _, err := rand.Read(rawNonce); err != nil {
		return domain.AuthChallenge{}, err
	}

	now := s.now().UTC()
	challenge := domain.AuthChallenge{
		ID:        uuid.NewString(),
		DeviceID:  device.ID,
		Nonce:     base64.StdEncoding.EncodeToString(rawNonce),
		CreatedAt: now,
		ExpiresAt: now.Add(s.cfg.ChallengeTTL),
	}

	if err := s.store.CreateChallenge(ctx, challenge); err != nil {
		return domain.AuthChallenge{}, err
	}
	s.logEvent(slog.LevelInfo, "auth challenge created", map[string]any{
		"device_id":    device.ID,
		"challenge_id": challenge.ID,
		"expires_at":   challenge.ExpiresAt,
	})
	return challenge, nil
}

func (s *Service) VerifyChallenge(ctx context.Context, input VerifyChallengeInput) (string, time.Time, string, error) {
	challenge, err := s.store.GetChallenge(ctx, input.ChallengeID)
	if err != nil {
		return "", time.Time{}, "", err
	}
	defer func() {
		if err := s.store.DeleteChallenge(ctx, challenge.ID); err != nil {
			s.logger.Warn("failed to delete auth challenge", "challenge_id", challenge.ID, "error", err)
		}
	}()

	if s.now().UTC().After(challenge.ExpiresAt) {
		return "", time.Time{}, "", ErrUnauthorized
	}

	device, err := s.store.GetDeviceByID(ctx, challenge.DeviceID)
	if err != nil {
		return "", time.Time{}, "", err
	}

	pubKey, err := base64.StdEncoding.DecodeString(device.AuthPublicKey)
	if err != nil || len(pubKey) != ed25519.PublicKeySize {
		return "", time.Time{}, "", ErrUnauthorized
	}
	signature, err := base64.StdEncoding.DecodeString(input.SignatureBase64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return "", time.Time{}, "", ErrUnauthorized
	}
	nonce, err := base64.StdEncoding.DecodeString(challenge.Nonce)
	if err != nil {
		return "", time.Time{}, "", ErrUnauthorized
	}
	if !ed25519.Verify(ed25519.PublicKey(pubKey), nonce, signature) {
		return "", time.Time{}, "", ErrUnauthorized
	}

	now := s.now().UTC()
	if err := s.store.TouchDevice(ctx, device.ID, now); err != nil {
		return "", time.Time{}, "", err
	}

	token, expiresAt, err := s.tokens.Issue(device.ID, now)
	if err != nil {
		return "", time.Time{}, "", err
	}
	s.logEvent(slog.LevelInfo, "auth verified", map[string]any{
		"device_id":  device.ID,
		"expires_at": expiresAt,
	})
	return token, expiresAt, device.ID, nil
}

func (s *Service) SendMessage(ctx context.Context, senderDeviceID string, input SendMessageInput) (domain.Message, error) {
	if input.IdempotencyKey == "" || len(input.IdempotencyKey) > 128 {
		return domain.Message{}, fmt.Errorf("%w: missing or invalid idempotency key", ErrInvalidInput)
	}
	if input.RecipientDeviceID == "" || input.RecipientDeviceID == senderDeviceID {
		return domain.Message{}, fmt.Errorf("%w: invalid recipient", ErrInvalidInput)
	}
	if len(input.Ciphertext) == 0 || len(input.Ciphertext) > s.cfg.MaxCiphertextBytes*2 {
		return domain.Message{}, fmt.Errorf("%w: invalid ciphertext size", ErrInvalidInput)
	}
	if err := validateBase64Payload(input.Ciphertext); err != nil {
		return domain.Message{}, fmt.Errorf("%w: ciphertext must be base64", ErrInvalidInput)
	}
	if err := validateBase64Payload(input.Nonce); err != nil {
		return domain.Message{}, fmt.Errorf("%w: nonce must be base64", ErrInvalidInput)
	}
	if !isAllowedMessageType(input.MessageType) {
		return domain.Message{}, fmt.Errorf("%w: invalid message type", ErrInvalidInput)
	}

	recipient, err := s.store.GetDeviceByID(ctx, input.RecipientDeviceID)
	if err != nil {
		return domain.Message{}, fmt.Errorf("%w: recipient not found", ErrInvalidInput)
	}

	if input.AttachmentID != nil {
		attachment, err := s.store.GetAttachment(ctx, *input.AttachmentID)
		if err != nil {
			return domain.Message{}, err
		}
		if attachment.DeviceID != senderDeviceID {
			return domain.Message{}, ErrAttachmentOwner
		}
	}

	now := s.now().UTC()
	message := domain.Message{
		ID:                uuid.NewString(),
		SenderDeviceID:    senderDeviceID,
		RecipientDeviceID: input.RecipientDeviceID,
		Ciphertext:        input.Ciphertext,
		Nonce:             input.Nonce,
		MessageType:       input.MessageType,
		AttachmentID:      input.AttachmentID,
		IdempotencyKey:    input.IdempotencyKey,
		CreatedAt:         now,
		ExpiresAt:         now.Add(s.cfg.MessageTTL),
	}
	created, err := s.store.CreateMessage(ctx, message)
	if err != nil {
		return domain.Message{}, err
	}
	s.logEvent(slog.LevelInfo, "message stored", map[string]any{
		"message_id":           created.ID,
		"sender_device_id":     senderDeviceID,
		"recipient_device_id":  input.RecipientDeviceID,
		"message_type":         input.MessageType,
		"ciphertext_length":    len(input.Ciphertext),
		"has_attachment":       input.AttachmentID != nil,
		"idempotency_key_size": len(input.IdempotencyKey),
	})
	s.notifyRecipient(ctx, recipient)
	return created, nil
}

func (s *Service) UpdatePushToken(ctx context.Context, deviceID string, input UpdatePushTokenInput) error {
	pushToken := strings.TrimSpace(input.PushToken)
	if len(pushToken) > 4096 {
		return fmt.Errorf("%w: invalid push token", ErrInvalidInput)
	}
	if err := s.store.UpdateDevicePushToken(ctx, deviceID, pushToken, s.now().UTC()); err != nil {
		return err
	}
	s.logEvent(slog.LevelInfo, "device push token updated", map[string]any{
		"device_id":      deviceID,
		"push_enabled":   pushToken != "",
		"push_token_len": len(pushToken),
	})
	return nil
}

func (s *Service) PullMessages(ctx context.Context, deviceID string, limit int) ([]domain.Message, error) {
	if limit <= 0 {
		limit = s.cfg.PullLimitDefault
	}
	if limit > s.cfg.PullLimitMax {
		limit = s.cfg.PullLimitMax
	}
	if err := s.store.TouchDevice(ctx, deviceID, s.now().UTC()); err != nil {
		return nil, err
	}
	messages, err := s.store.PullMessages(ctx, deviceID, limit, s.now().UTC())
	if err != nil {
		return nil, err
	}
	s.logEvent(slog.LevelInfo, "messages pulled", map[string]any{
		"device_id": deviceID,
		"limit":     limit,
		"count":     len(messages),
	})
	return messages, nil
}

func (s *Service) AckDeleteMessages(ctx context.Context, deviceID string, messageIDs []string) (int64, error) {
	if len(messageIDs) == 0 || len(messageIDs) > s.cfg.MaxACKItems {
		return 0, fmt.Errorf("%w: invalid ack payload", ErrInvalidInput)
	}
	deleted, err := s.store.AckDeleteMessages(ctx, deviceID, messageIDs)
	if err != nil {
		return 0, err
	}
	s.logEvent(slog.LevelInfo, "messages acknowledged", map[string]any{
		"device_id":     deviceID,
		"requested_ids": len(messageIDs),
		"deleted_count": deleted,
	})
	return deleted, nil
}

func (s *Service) InitAttachmentUpload(ctx context.Context, deviceID string, input UploadInitInput) (domain.Attachment, string, error) {
	if s.objects == nil {
		return domain.Attachment{}, "", errors.New("object store is not configured")
	}
	if input.CiphertextSize <= 0 || input.CiphertextSize > s.cfg.MaxAttachmentBytes {
		return domain.Attachment{}, "", fmt.Errorf("%w: invalid attachment size", ErrInvalidInput)
	}
	normalizedMIME, err := normalizeAttachmentMIME(input.MIMEType)
	if err != nil {
		return domain.Attachment{}, "", fmt.Errorf("%w: unsupported mime type", ErrInvalidInput)
	}
	now := s.now().UTC()
	attachment := domain.Attachment{
		ID:             uuid.NewString(),
		DeviceID:       deviceID,
		ObjectKey:      fmt.Sprintf("%s/%s", deviceID, uuid.NewString()),
		CiphertextSize: input.CiphertextSize,
		MIMEType:       normalizedMIME,
		CreatedAt:      now,
		ExpiresAt:      now.Add(s.cfg.MessageTTL),
	}
	attachment, err = s.store.CreateAttachment(ctx, attachment)
	if err != nil {
		return domain.Attachment{}, "", err
	}
	url, err := s.objects.PresignedPut(ctx, attachment.ObjectKey, attachment.MIMEType)
	if err != nil {
		return domain.Attachment{}, "", err
	}
	s.logEvent(slog.LevelInfo, "attachment upload initialized", map[string]any{
		"device_id":       deviceID,
		"attachment_id":   attachment.ID,
		"ciphertext_size": attachment.CiphertextSize,
		"mime_type":       attachment.MIMEType,
	})
	return attachment, url.String(), nil
}

func (s *Service) AttachmentDownloadURL(ctx context.Context, deviceID, attachmentID string) (domain.Attachment, string, error) {
	if s.objects == nil {
		return domain.Attachment{}, "", errors.New("object store is not configured")
	}
	attachment, err := s.GetAccessibleAttachment(ctx, deviceID, attachmentID)
	if err != nil {
		return domain.Attachment{}, "", err
	}
	url, err := s.objects.PresignedGet(ctx, attachment.ObjectKey)
	if err != nil {
		return domain.Attachment{}, "", err
	}
	s.logEvent(slog.LevelInfo, "attachment download issued", map[string]any{
		"device_id":     deviceID,
		"attachment_id": attachmentID,
	})
	return attachment, url.String(), nil
}

func (s *Service) GetOwnedAttachment(ctx context.Context, deviceID, attachmentID string) (domain.Attachment, error) {
	if s.objects == nil {
		return domain.Attachment{}, errors.New("object store is not configured")
	}
	attachment, err := s.store.GetAttachment(ctx, attachmentID)
	if err != nil {
		return domain.Attachment{}, err
	}
	if attachment.DeviceID != deviceID {
		return domain.Attachment{}, ErrUnauthorized
	}
	return attachment, nil
}

func (s *Service) GetAccessibleAttachment(ctx context.Context, deviceID, attachmentID string) (domain.Attachment, error) {
	if s.objects == nil {
		return domain.Attachment{}, errors.New("object store is not configured")
	}
	allowed, err := s.store.CanAccessAttachment(ctx, attachmentID, deviceID)
	if err != nil {
		return domain.Attachment{}, err
	}
	if !allowed {
		return domain.Attachment{}, ErrUnauthorized
	}
	return s.store.GetAttachment(ctx, attachmentID)
}

func (s *Service) UploadAttachmentContent(ctx context.Context, deviceID, attachmentID, mimeType string, size int64, body io.Reader) (domain.Attachment, error) {
	attachment, err := s.GetOwnedAttachment(ctx, deviceID, attachmentID)
	if err != nil {
		return domain.Attachment{}, err
	}
	if size <= 0 || size != attachment.CiphertextSize {
		return domain.Attachment{}, fmt.Errorf("%w: attachment size mismatch", ErrInvalidInput)
	}
	if mimeType != "" {
		normalizedMIME, err := normalizeAttachmentMIME(mimeType)
		if err != nil {
			return domain.Attachment{}, fmt.Errorf("%w: attachment mime type mismatch", ErrInvalidInput)
		}
		if normalizedMIME != attachment.MIMEType {
			return domain.Attachment{}, fmt.Errorf("%w: attachment mime type mismatch", ErrInvalidInput)
		}
	}
	if err := s.objects.PutObject(ctx, attachment.ObjectKey, body, size, attachment.MIMEType); err != nil {
		return domain.Attachment{}, err
	}
	s.logEvent(slog.LevelInfo, "attachment uploaded", map[string]any{
		"device_id":       deviceID,
		"attachment_id":   attachment.ID,
		"ciphertext_size": attachment.CiphertextSize,
		"mime_type":       attachment.MIMEType,
	})
	return attachment, nil
}

func (s *Service) OpenAttachmentContent(ctx context.Context, deviceID, attachmentID string) (domain.Attachment, io.ReadCloser, error) {
	attachment, err := s.GetAccessibleAttachment(ctx, deviceID, attachmentID)
	if err != nil {
		return domain.Attachment{}, nil, err
	}
	reader, err := s.objects.GetObject(ctx, attachment.ObjectKey)
	if err != nil {
		return domain.Attachment{}, nil, err
	}
	s.logEvent(slog.LevelInfo, "attachment streamed", map[string]any{
		"device_id":     deviceID,
		"attachment_id": attachment.ID,
		"mime_type":     attachment.MIMEType,
	})
	return attachment, reader, nil
}

func (s *Service) CleanupExpired(ctx context.Context) error {
	now := s.now().UTC()
	if err := s.store.DeleteExpiredChallenges(ctx, now); err != nil {
		return err
	}
	if err := s.store.DeleteExpiredMessages(ctx, now); err != nil {
		return err
	}
	attachments, err := s.store.ListExpiredAttachments(ctx, now)
	if err != nil {
		return err
	}
	for _, attachment := range attachments {
		if err := s.objects.RemoveObject(ctx, attachment.ObjectKey); err != nil {
			s.logger.Warn("failed to remove expired object", "attachment_id", attachment.ID, "object_key", attachment.ObjectKey, "error", err)
			continue
		}
		if err := s.store.DeleteAttachment(ctx, attachment.ID); err != nil && !errors.Is(err, storage.ErrNotFound) {
			s.logger.Warn("failed to delete attachment metadata", "attachment_id", attachment.ID, "error", err)
		}
	}
	return nil
}

func (s *Service) RunCleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.CleanupExpired(ctx); err != nil {
				s.logger.Warn("cleanup cycle failed", "error", err)
			}
		}
	}
}

func (s *Service) Health(ctx context.Context) error {
	if err := s.store.Health(ctx); err != nil {
		return err
	}
	if s.objects == nil {
		return nil
	}
	return s.objects.Health(ctx)
}

func (s *Service) EnsureDebugDevice(ctx context.Context, publicKey string) (domain.Device, bool, error) {
	if err := validateBase64Key(publicKey); err != nil {
		return domain.Device{}, false, fmt.Errorf("%w: invalid public key", ErrInvalidInput)
	}

	device, err := s.store.GetDeviceByAuthKey(ctx, publicKey)
	if err == nil {
		s.logEvent(slog.LevelInfo, "debug device reused", map[string]any{
			"device_id": device.ID,
		})
		return device, false, nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return domain.Device{}, false, err
	}

	device, err = s.store.CreateDevice(ctx, publicKey, publicKey, s.now().UTC())
	if err != nil {
		return domain.Device{}, false, err
	}
	s.logEvent(slog.LevelWarn, "debug device auto-registered", map[string]any{
		"device_id": device.ID,
	})
	return device, true, nil
}

func (s *Service) ResolveDeviceByPublicKey(ctx context.Context, publicKey string) (domain.Device, error) {
	if err := validateBase64Key(publicKey); err != nil {
		return domain.Device{}, fmt.Errorf("%w: invalid public key", ErrInvalidInput)
	}
	return s.store.GetDeviceByAuthKey(ctx, publicKey)
}

func (s *Service) IssueDebugToken(ctx context.Context, deviceID string) (string, time.Time, error) {
	now := s.now().UTC()
	if err := s.store.TouchDevice(ctx, deviceID, now); err != nil {
		return "", time.Time{}, err
	}
	token, expiresAt, err := s.tokens.Issue(deviceID, now)
	if err != nil {
		return "", time.Time{}, err
	}
	s.logEvent(slog.LevelWarn, "debug token issued", map[string]any{
		"device_id":  deviceID,
		"expires_at": expiresAt,
	})
	return token, expiresAt, nil
}

func (s *Service) logEvent(level slog.Level, message string, fields map[string]any) {
	args := make([]any, 0, len(fields)*2)
	for key, value := range fields {
		args = append(args, key, value)
	}
	switch {
	case level >= slog.LevelError:
		s.logger.Error(message, args...)
	case level >= slog.LevelWarn:
		s.logger.Warn(message, args...)
	default:
		s.logger.Info(message, args...)
	}
	if s.logbook != nil {
		s.logbook.Add(level, message, fields)
	}
}

func (s *Service) notifyRecipient(ctx context.Context, recipient domain.Device) {
	if strings.TrimSpace(recipient.PushToken) == "" {
		return
	}
	if err := s.push.SendActivity(ctx, recipient.PushToken); err != nil {
		if errors.Is(err, push.ErrPushTokenInvalid) {
			if clearErr := s.store.UpdateDevicePushToken(ctx, recipient.ID, "", s.now().UTC()); clearErr != nil {
				s.logger.Warn("failed to clear invalid push token", "device_id", recipient.ID, "error", clearErr)
			}
			s.logger.Info("invalid push token cleared", "device_id", recipient.ID)
			return
		}
		s.logger.Warn("push activity send failed", "device_id", recipient.ID, "error", err)
	}
}

func validateBase64Key(value string) error {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 {
		return ErrInvalidInput
	}
	return nil
}

func validateBase64Payload(value string) error {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 {
		return ErrInvalidInput
	}
	return nil
}

func isAllowedMessageType(value string) bool {
	switch value {
	case "text", "image", "file", "video":
		return true
	default:
		return false
	}
}

func normalizeAttachmentMIME(value string) (string, error) {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "application/octet-stream", nil
	}
	if len(value) > 255 {
		return "", ErrInvalidInput
	}
	mediaType, _, err := mime.ParseMediaType(value)
	if err != nil {
		return "", err
	}
	if mediaType == "" || !strings.Contains(mediaType, "/") {
		return "", ErrInvalidInput
	}
	return mediaType, nil
}
