package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"

	"xam/linux_server/internal/domain"
)

var ErrNotFound = errors.New("not found")

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(databaseURL string) (*PostgresStore, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)

	return &PostgresStore{db: db}, nil
}

func (s *PostgresStore) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *PostgresStore) Close() error {
	return s.db.Close()
}

func (s *PostgresStore) CreateDevice(ctx context.Context, authKey, exchangeKey string, now time.Time) (domain.Device, error) {
	deviceID := uuid.NewString()
	query := `
		INSERT INTO devices (device_id, auth_public_key, exchange_public_key, created_at, last_seen_at, status)
		VALUES ($1, $2, $3, $4, $4, 'active')
		RETURNING device_id, auth_public_key, exchange_public_key, created_at, last_seen_at, status
	`
	var device domain.Device
	err := s.db.QueryRowContext(ctx, query, deviceID, authKey, exchangeKey, now).Scan(
		&device.ID,
		&device.AuthPublicKey,
		&device.ExchangePublicKey,
		&device.CreatedAt,
		&device.LastSeenAt,
		&device.Status,
	)
	if err != nil {
		return domain.Device{}, err
	}
	return device, nil
}

func (s *PostgresStore) GetDeviceByID(ctx context.Context, deviceID string) (domain.Device, error) {
	query := `
		SELECT device_id, auth_public_key, exchange_public_key, created_at, last_seen_at, status
		FROM devices
		WHERE device_id = $1
	`
	var device domain.Device
	err := s.db.QueryRowContext(ctx, query, deviceID).Scan(
		&device.ID,
		&device.AuthPublicKey,
		&device.ExchangePublicKey,
		&device.CreatedAt,
		&device.LastSeenAt,
		&device.Status,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Device{}, ErrNotFound
	}
	if err != nil {
		return domain.Device{}, err
	}
	return device, nil
}

func (s *PostgresStore) GetDeviceByAuthKey(ctx context.Context, authKey string) (domain.Device, error) {
	query := `
		SELECT device_id, auth_public_key, exchange_public_key, created_at, last_seen_at, status
		FROM devices
		WHERE auth_public_key = $1
	`
	var device domain.Device
	err := s.db.QueryRowContext(ctx, query, authKey).Scan(
		&device.ID,
		&device.AuthPublicKey,
		&device.ExchangePublicKey,
		&device.CreatedAt,
		&device.LastSeenAt,
		&device.Status,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Device{}, ErrNotFound
	}
	if err != nil {
		return domain.Device{}, err
	}
	return device, nil
}

func (s *PostgresStore) TouchDevice(ctx context.Context, deviceID string, now time.Time) error {
	result, err := s.db.ExecContext(ctx, `UPDATE devices SET last_seen_at = $2 WHERE device_id = $1`, deviceID, now)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) CreateChallenge(ctx context.Context, challenge domain.AuthChallenge) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO auth_challenges (challenge_id, device_id, nonce, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)
	`, challenge.ID, challenge.DeviceID, challenge.Nonce, challenge.CreatedAt, challenge.ExpiresAt)
	return err
}

func (s *PostgresStore) GetChallenge(ctx context.Context, challengeID string) (domain.AuthChallenge, error) {
	var challenge domain.AuthChallenge
	err := s.db.QueryRowContext(ctx, `
		SELECT challenge_id, device_id, nonce, created_at, expires_at
		FROM auth_challenges
		WHERE challenge_id = $1
	`, challengeID).Scan(&challenge.ID, &challenge.DeviceID, &challenge.Nonce, &challenge.CreatedAt, &challenge.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.AuthChallenge{}, ErrNotFound
	}
	if err != nil {
		return domain.AuthChallenge{}, err
	}
	return challenge, nil
}

func (s *PostgresStore) DeleteChallenge(ctx context.Context, challengeID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_challenges WHERE challenge_id = $1`, challengeID)
	return err
}

func (s *PostgresStore) CreateAttachment(ctx context.Context, attachment domain.Attachment) (domain.Attachment, error) {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO attachments (attachment_id, device_id, object_key, ciphertext_size, mime_type, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, attachment.ID, attachment.DeviceID, attachment.ObjectKey, attachment.CiphertextSize, attachment.MIMEType, attachment.CreatedAt, attachment.ExpiresAt)
	if err != nil {
		return domain.Attachment{}, err
	}
	return attachment, nil
}

func (s *PostgresStore) GetAttachment(ctx context.Context, attachmentID string) (domain.Attachment, error) {
	var attachment domain.Attachment
	err := s.db.QueryRowContext(ctx, `
		SELECT attachment_id, device_id, object_key, ciphertext_size, mime_type, created_at, expires_at
		FROM attachments
		WHERE attachment_id = $1
	`, attachmentID).Scan(
		&attachment.ID,
		&attachment.DeviceID,
		&attachment.ObjectKey,
		&attachment.CiphertextSize,
		&attachment.MIMEType,
		&attachment.CreatedAt,
		&attachment.ExpiresAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Attachment{}, ErrNotFound
	}
	if err != nil {
		return domain.Attachment{}, err
	}
	return attachment, nil
}

func (s *PostgresStore) CanAccessAttachment(ctx context.Context, attachmentID, deviceID string) (bool, error) {
	var allowed bool
	err := s.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM attachments a
			LEFT JOIN messages m ON m.attachment_id = a.attachment_id
			WHERE a.attachment_id = $1
			  AND (
				a.device_id = $2 OR
				m.sender_device_id = $2 OR
				m.recipient_device_id = $2
			  )
		)
	`, attachmentID, deviceID).Scan(&allowed)
	if err != nil {
		return false, err
	}
	return allowed, nil
}

func (s *PostgresStore) CreateMessage(ctx context.Context, message domain.Message) (domain.Message, error) {
	query := `
		INSERT INTO messages (
			message_id, sender_device_id, recipient_device_id, ciphertext, nonce, message_type,
			attachment_id, idempotency_key, created_at, expires_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (sender_device_id, idempotency_key)
		DO UPDATE SET sender_device_id = EXCLUDED.sender_device_id
		RETURNING message_id, sender_device_id, recipient_device_id, ciphertext, nonce, message_type, attachment_id, idempotency_key, created_at, expires_at
	`
	var attachmentID sql.NullString
	err := s.db.QueryRowContext(
		ctx,
		query,
		message.ID,
		message.SenderDeviceID,
		message.RecipientDeviceID,
		message.Ciphertext,
		message.Nonce,
		message.MessageType,
		message.AttachmentID,
		message.IdempotencyKey,
		message.CreatedAt,
		message.ExpiresAt,
	).Scan(
		&message.ID,
		&message.SenderDeviceID,
		&message.RecipientDeviceID,
		&message.Ciphertext,
		&message.Nonce,
		&message.MessageType,
		&attachmentID,
		&message.IdempotencyKey,
		&message.CreatedAt,
		&message.ExpiresAt,
	)
	if err != nil {
		return domain.Message{}, err
	}
	if attachmentID.Valid {
		message.AttachmentID = &attachmentID.String
	}
	return message, nil
}

func (s *PostgresStore) PullMessages(ctx context.Context, recipientDeviceID string, limit int, now time.Time) ([]domain.Message, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT message_id, sender_device_id, recipient_device_id, ciphertext, nonce, message_type, attachment_id, idempotency_key, created_at, expires_at
		FROM messages
		WHERE recipient_device_id = $1 AND expires_at > $2
		ORDER BY created_at ASC
		LIMIT $3
	`, recipientDeviceID, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var messages []domain.Message
	for rows.Next() {
		var message domain.Message
		var attachmentID sql.NullString
		if err := rows.Scan(
			&message.ID,
			&message.SenderDeviceID,
			&message.RecipientDeviceID,
			&message.Ciphertext,
			&message.Nonce,
			&message.MessageType,
			&attachmentID,
			&message.IdempotencyKey,
			&message.CreatedAt,
			&message.ExpiresAt,
		); err != nil {
			return nil, err
		}
		if attachmentID.Valid {
			message.AttachmentID = &attachmentID.String
		}
		messages = append(messages, message)
	}
	return messages, rows.Err()
}

func (s *PostgresStore) AckDeleteMessages(ctx context.Context, recipientDeviceID string, messageIDs []string) (int64, error) {
	if len(messageIDs) == 0 {
		return 0, nil
	}
	query := `
		DELETE FROM messages
		WHERE recipient_device_id = $1
		  AND message_id = ANY($2)
	`
	result, err := s.db.ExecContext(ctx, query, recipientDeviceID, messageIDs)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *PostgresStore) DeleteExpiredChallenges(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM auth_challenges WHERE expires_at <= $1`, now)
	return err
}

func (s *PostgresStore) DeleteExpiredMessages(ctx context.Context, now time.Time) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM messages WHERE expires_at <= $1`, now)
	return err
}

func (s *PostgresStore) ListExpiredAttachments(ctx context.Context, now time.Time) ([]domain.Attachment, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT a.attachment_id, a.device_id, a.object_key, a.ciphertext_size, a.mime_type, a.created_at, a.expires_at
		FROM attachments a
		LEFT JOIN messages m ON m.attachment_id = a.attachment_id
		WHERE a.expires_at <= $1 OR m.attachment_id IS NULL
	`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var attachments []domain.Attachment
	for rows.Next() {
		var attachment domain.Attachment
		if err := rows.Scan(
			&attachment.ID,
			&attachment.DeviceID,
			&attachment.ObjectKey,
			&attachment.CiphertextSize,
			&attachment.MIMEType,
			&attachment.CreatedAt,
			&attachment.ExpiresAt,
		); err != nil {
			return nil, err
		}
		attachments = append(attachments, attachment)
	}
	return attachments, rows.Err()
}

func (s *PostgresStore) DeleteAttachment(ctx context.Context, attachmentID string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM attachments WHERE attachment_id = $1`, attachmentID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *PostgresStore) Health(ctx context.Context) error {
	var one int
	if err := s.db.QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil {
		return fmt.Errorf("db health check failed: %w", err)
	}
	return nil
}
