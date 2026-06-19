# Breezy — Auth Service

Gère l'inscription, la connexion et les tokens JWT pour l'application Breezy.

## Ce que fait ce service

- Inscription / connexion des utilisateurs
- Génération de tokens JWT (access token 15 min + refresh token 7 jours en cookie)
- Révocation des tokens (logout)
- Bannissement d'utilisateurs (endpoint interne, appelé par le user-service)
- Synchronisation automatique du nouvel utilisateur vers le user-service à l'inscription

## Variables d'environnement

Copie `.env.example` en `.env` et remplis les valeurs :

```bash
cp .env.example .env
```

| Variable | Description |
|---|---|
| `PORT` | Port d'écoute (défaut : 3001) |
| `DATABASE_URL` | URL de connexion PostgreSQL |
| `JWT_SECRET` | Clé secrète pour signer les tokens JWT |
| `JWT_EXPIRES_IN` | Durée de vie de l'access token (ex : `15m`) |
| `REFRESH_TOKEN_DAYS` | Durée de vie du refresh token en jours (défaut : 7) |
| `BCRYPT_ROUNDS` | Nombre de rounds bcrypt pour le hash des mots de passe (défaut : 12) |
| `INTERNAL_SECRET` | Secret partagé pour les appels entre services |
| `USER_SERVICE_URL` | URL du user-service |

> `INTERNAL_SECRET` doit avoir la même valeur dans tous les services.

## Lancer en développement

```bash
npm install
npm run dev
```

Le service tourne sur `http://localhost:3001`.

## Lancer les tests

Assure-toi d'avoir une base PostgreSQL de test (`breezy_auth_test`) accessible, puis :

```bash
npm test
```

Les tests utilisent `DATABASE_URL_TEST` si défini, sinon ils se connectent à `localhost:5432/breezy_auth_test`.

## Lancer avec Docker

```bash
docker build -t breezy-auth .
docker run -p 3001:3001 --env-file .env breezy-auth
```

## Endpoints

| Méthode | Route | Description |
|---|---|---|
| `POST` | `/auth/register` | Inscription |
| `POST` | `/auth/login` | Connexion |
| `POST` | `/auth/refresh` | Renouveler l'access token |
| `POST` | `/auth/logout` | Déconnexion |
| `GET` | `/auth/me` | Infos de l'utilisateur connecté |
| `POST` | `/auth/internal/ban` | Bannir un utilisateur (interne uniquement) |
| `GET` | `/health` | Vérification que le service est up |

### Validation à l'inscription

- `username` : 3 à 50 caractères, lettres/chiffres/underscore uniquement
- `email` : format email valide
- `password` : minimum 8 caractères, au moins 1 majuscule et 1 chiffre

## Structure du projet

```
src/
├── config/       # Connexion base de données (Sequelize)
├── controllers/  # Logique métier
├── middleware/   # Validation et identité
├── models/       # Modèles Sequelize (User, RefreshToken)
├── routes/       # Définition des routes
└── utils/        # Utilitaires JWT
tests/
└── auth.test.js  # Tests d'intégration
```
