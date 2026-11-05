# Breezy: auth service

Accounts and authentication for [Breezy](https://github.com/El-Pouleto-ultimate/breezy-infra), a Twitter-like
social network built as microservices: registration, login with JWT access tokens and rotating refresh sessions,
password and username changes, admin account creation, and internal endpoints the other services use for bans
and role lookups.

Team project at CESI École d'Ingénieurs (distributed applications, June 2026).

Stack: Node.js 20, Express 5, Sequelize 6 on PostgreSQL, jsonwebtoken, bcryptjs, helmet, express-validator.

## API

| Method | Path | Access |
|---|---|---|
| POST | `/auth/register` | public |
| POST | `/auth/login` | public |
| POST | `/auth/refresh` | public |
| POST | `/auth/logout` | public |
| GET | `/auth/me` | signed in |
| POST | `/auth/change-password` | signed in |
| PATCH | `/auth/username` | signed in |
| POST | `/auth/admin/create-user` | admin |
| POST | `/auth/internal/ban` | internal |
| GET | `/auth/internal/users/:id/role` | internal |
| GET | `/health` | public |

"Signed in" routes read the `x-user-id` and `x-user-role` headers that the gateway sets once it has checked the
JWT. "Internal" routes require the `x-internal-secret` header shared by the services.

## Configuration

Copy `.env.example` to `.env`. Variables: `PORT`, `DATABASE_URL`, `JWT_SECRET`, `JWT_EXPIRES_IN`,
`REFRESH_TOKEN_DAYS`, `BCRYPT_ROUNDS`, `INTERNAL_SECRET`, `USER_SERVICE_URL`, `CORS_ORIGIN`.

## Run and test

The whole stack runs with Docker Compose from [breezy-infra](https://github.com/El-Pouleto-ultimate/breezy-infra).
On its own:

```bash
npm install
npm run dev     # or: npm start
npm test        # 13 integration tests (Jest + supertest) against PostgreSQL
```

GitHub Actions runs the tests against PostgreSQL 15 on every push and pull request
([`ci.yml`](.github/workflows/ci.yml)).

## Team

[Estebge](https://github.com/Estebge), [haguetm](https://github.com/haguetm),
[Jessica14112005](https://github.com/Jessica14112005), [Tuture57](https://github.com/Tuture57).
