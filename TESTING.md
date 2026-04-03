# Server Testing

## 1. Start the stack

```bash
cd /home/zorg/xam/linux_server
cp .env.example .env
```

Enable debug endpoints for transport testing:

```bash
echo "DEBUG_API_ENABLED=true" >> .env
```

Run services:

```bash
docker compose --env-file .env up -d --build
curl http://127.0.0.1:8080/healthz
```

## 2. Prepare two test keys

```bash
KEY_A=$(openssl rand -base64 32 | tr -d '\n')
KEY_B=$(openssl rand -base64 32 | tr -d '\n')
echo "$KEY_A"
echo "$KEY_B"
```

## 3. Send a message from A to B

```bash
cd /home/zorg/xam/go_transport
go run ./cmd/xam-debug-client \
  -base-url http://127.0.0.1:8080 \
  -self-key "$KEY_A" \
  -peer-key "$KEY_B" \
  -send "hello from A"
```

## 4. Pull on B

```bash
cd /home/zorg/xam/go_transport
go run ./cmd/xam-debug-client \
  -base-url http://127.0.0.1:8080 \
  -self-key "$KEY_B" \
  -pull
```

Expected result:
- message appears exactly once on first pull
- message is deleted only after `ack-delete`
- repeated pull after ack returns zero messages

## 5. Inspect detailed debug logs

```bash
cd /home/zorg/xam/go_transport
go run ./cmd/xam-debug-client \
  -base-url http://127.0.0.1:8080 \
  -self-key "$KEY_A" \
  -logs
```

## 6. Two-phone manual test

1. Install the debug APK on both phones.
2. Open `Contacts`, then `Debug`.
3. Set the same server URL on both phones.
4. Press `Connect` on both phones.
5. Exchange QR codes and add each other to contacts.
6. Open chat on phone A and send a message.
7. On phone B open the same chat and press `Sync`.
8. Confirm the message appears and then disappears from server logs after `ack-delete`.

## Notes

- For real phones the server URL must be reachable from both devices.
- If the server runs behind nginx, use the public HTTPS URL instead of `127.0.0.1`.
- Debug endpoints are for testing only and should stay disabled in production.
