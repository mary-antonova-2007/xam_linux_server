# Deployment Notes

## Safe coexistence on an existing server

This stack is prepared to run alongside other websites and Docker projects:

- PostgreSQL is internal only and is not published to the host
- MinIO is internal only and is not published to the host
- The API is bound to `127.0.0.1:8080` by default

That means the service can run without taking over public ports `80` and `443`, and without conflicting with host ports `5432`, `9000`, or `9001`.

## First deployment

```bash
git clone git@github.com:mary-antonova-2007/xam_linux_server.git
cd xam_linux_server
cp .env.server.example .env
docker compose --env-file .env up -d --build
```

## Health check

```bash
curl http://127.0.0.1:8080/healthz
```

## Useful commands

```bash
docker compose --env-file .env ps
docker compose --env-file .env logs -f app
docker compose --env-file .env pull
docker compose --env-file .env up -d --build
```
