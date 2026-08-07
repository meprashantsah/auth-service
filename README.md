# Auth Service

JWT-based Authentication & Authorization Microservice.

## Tech Stack

- Spring Boot 4.2
- Java 25
- Spring Security 7
- PostgreSQL 16+
- Redis 7+
- Gradle

## Features

- User registration & login
- JWT Access Token (15 min) + Refresh Token (7 days)
- RS256 asymmetric signing
- Role-Based Access Control (RBAC)
- Token refresh with rotation
- Token blacklist (Redis) for logout
- Account lockout after failed attempts

## Setup

### 1. Generate RSA Key Pair

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

Paste the contents into `application.yaml` under `jwt.private-key` and `jwt.public-key`.

### 2. Start PostgreSQL

```bash
docker run -d \
  --name auth-postgres \
  -e POSTGRES_DB=auth_db \
  -e POSTGRES_USER=auth_user \
  -e POSTGRES_PASSWORD=auth_pass \
  -p 5432:5432 \
  postgres:16-alpine
```

### 3. Start Redis

```bash
docker run -d -p 6379:6379 --name redis redis:7-alpine
```

### 4. Run

```bash
./gradlew bootRun
```

## API Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | /api/auth/register | No | Create account |
| POST | /api/auth/login | No | Login, get tokens |
| POST | /api/auth/refresh | No | Refresh access token |
| POST | /api/auth/logout | Yes | Revoke tokens |
| POST | /api/auth/validate | No | Validate token |
| GET | /api/auth/me | Yes | Current user |
| GET | /api/auth/users | Admin | List users |
| POST | /api/auth/roles | Admin | Create role |
| GET | /api/auth/roles | Admin | List roles |
| POST | /api/auth/permissions | Admin | Create permission |
| GET | /api/auth/permissions | Admin | List permissions |

## Integration with API Gateway

1. Copy the **public key** from this service to the Gateway's `application.yaml`
2. Gateway validates tokens locally using the public key
3. Gateway forwards `X-User-Id`, `X-Username`, `X-Roles` headers to downstream services
