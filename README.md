# Auth Service

JWT-based Authentication & Authorization Identity microservice.

## Tech Stack

- Spring Boot 4.x
- Java 25
- Spring Security 7
- PostgreSQL 16+
- Redis 7+
- Flyway
- Eureka client
- Load-balanced `RestClient` for service-to-service calls

## Responsibility

`auth-service` owns the **identity & authorization** domain only:

- Account credentials (username / password hash, lock state)
- Token issuance & validation
- Roles & permissions (RBAC)

User **profiles** (display name, avatar, bio, status, search) live in the
separate `user-service`.

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/auth/register | No | Create account (also creates profile in user-service) |
| POST | /api/auth/login | No | Login, get tokens |
| POST | /api/auth/refresh | No | Refresh access token |
| POST | /api/auth/logout | Yes | Revoke tokens |
| POST | /api/auth/validate | No | Validate token |
| GET  | /api/auth/me | Yes | Current identity (id, username, roles, permissions) |
| POST | /api/auth/roles | Admin | Create role |
| GET  | /api/auth/roles | Admin | List roles |
| POST | /api/auth/permissions | Admin | Create permission |
| GET  | /api/auth/permissions | Admin | List permissions |
| POST/DELETE | /api/auth/users/{id}/roles | Admin | Assign / remove role on identity user |

RBAC role/permission assignment is applied to **identity** users, while the
user directory (search, profile) is served by `user-service`.

## Setup

### 1. Generate RSA key pair

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

Set the values in `application-local.yaml` (gitignored) or via the
`JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` environment variables.
The **public key** must be copied to the gateway's `application.yaml`.

### 2. Start PostgreSQL + Redis

```bash
docker run -d --name auth-postgres \
  -e POSTGRES_DB=auth_db -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -p 5432:5432 postgres:16-alpine

docker run -d -p 6379:6379 --name redis redis:7-alpine
```

Schema is managed by Flyway migrations in `src/main/resources/db/migration`.

### 3. Run

```bash
./gradlew bootRun
```

Runs on a random port (`server.port: 0`) and registers with Eureka.

## Integration with API Gateway

1. Copy the **public key** to the Gateway's `application.yaml`
2. Gateway validates tokens locally using that public key
3. Gateway forwards `X-User-Id`, `X-Username` headers to downstream services

## Integration with User Service

On registration, `AuthService` calls the user-service internal API
(`POST http://user-service/internal/users`, guarded by `X-Internal-Key`) to
create the user profile with the same user id. Failure rolls the transaction
back so an account is never half-created.