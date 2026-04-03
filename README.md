# Linux Server

Dockerized Go backend for the messenger monorepo. The service stores only encrypted message payloads and encrypted attachment blobs, handles device authentication, message pull, and explicit ack-delete delivery semantics.

## Important security note

The original plan requires both `X25519` for E2EE and `challenge-signature` authentication. Because X25519 keys are not signature keys, the server registers two public keys per device:

- `auth_public_key`: `Ed25519` public key used only for challenge signing
- `exchange_public_key`: `X25519` public key used by clients for end-to-end encryption

The server does not decrypt payloads and does not inspect attachment contents.

## Endpoints

- `POST /devices/register`
- `POST /auth/challenge`
- `POST /auth/verify`
- `POST /messages`
- `GET /messages/pull`
- `POST /messages/ack-delete`
- `POST /attachments/upload-init`
- `GET /attachments/download`
- `GET /healthz`

## Local run

```bash
docker compose up --build
```

Server:

- API: `http://localhost:8080`
- MinIO: `http://localhost:9000`
- MinIO Console: `http://localhost:9001`

## Request examples

Register device:

```json
{
  "auth_public_key": "BASE64_ED25519_PUBLIC_KEY",
  "exchange_public_key": "BASE64_X25519_PUBLIC_KEY"
}
```

Create challenge:

```json
{
  "auth_public_key": "BASE64_ED25519_PUBLIC_KEY"
}
```

Verify challenge:

```json
{
  "challenge_id": "uuid",
  "signature": "BASE64_ED25519_SIGNATURE"
}
```

Send message:

```json
{
  "recipient_device_id": "uuid",
  "ciphertext": "BASE64_CIPHERTEXT",
  "nonce": "BASE64_NONCE",
  "message_type": "text",
  "attachment_id": null
}
```
