# Communication_LTD - Secure Web System (Part A)

Web information system for **Communication_LTD**, a fictional company that markets internet
packages. Part A focuses on **secure development**, centred on the user registration mechanism.

| Layer    | Technology                                                       |
| -------- | ---------------------------------------------------------------- |
| Client   | ReactJS (JavaScript) + Vite, Axios, Zod                          |
| Server   | Node.js, Express 5, Sequelize ORM, Zod, Helmet, express-rate-limit |
| Database | SQLite (local file, `sqlite3` driver)                            |
| Language | JavaScript end to end                                            |

---

## Folder structure

```
Comunication_LTD/
├── package.json            # root: only "concurrently" + scripts to run both parts
├── .gitignore              # node_modules, .env, SQLite files, build output
├── README.md
├── backend/                # Express API (CommonJS) - its own package.json & node_modules
│   ├── index.js            # entry point: validate config, connect DB, start server
│   ├── .env.example        # template for backend/.env (the real .env is git-ignored)
│   ├── config/
│   │   └── password-policy.json      # administrator-editable password policy
│   ├── data/               # database.sqlite (created at runtime, git-ignored)
│   └── src/
│       ├── app.js                    # Express app: helmet, CORS, JSON limit, routes, errors
│       ├── config/env.js             # loads + validates .env (fail fast)
│       ├── config/passwordPolicy.js  # loads + validates password-policy.json (fail fast)
│       ├── config/database.js        # Sequelize / SQLite connection
│       ├── models/                   # User, PasswordHistory, associations
│       ├── validation/userSchemas.js # Zod registration schema built from the policy
│       ├── utils/crypto.js           # salt, HMAC-SHA256, timing-safe verify
│       ├── middleware/               # validate (Zod), errorHandler
│       └── routes/auth.routes.js     # /api/auth/password-policy, /api/auth/register
└── frontend/               # React app (ES modules) - its own package.json & node_modules
    ├── .env.example        # optional API URL override
    ├── vite.config.js      # fixed port 5173 (must match backend CORS_ORIGIN)
    └── src/
        ├── App.jsx
        ├── api/client.js                    # Axios instance + error mapping
        ├── validation/registerSchema.js     # client-side Zod rules (built from the server policy)
        └── components/Register/             # Register.jsx + Register.css
```

Backend and frontend are fully separate npm projects (no npm workspaces), so their
dependencies never conflict. The root `package.json` only orchestrates them.

---

## Setup

Prerequisites: **Node.js 22.13 or newer** (developed on 26.13) and npm 11+. The minimum comes
from the tooling: `concurrently` 10 needs Node 22+, ESLint 10 and Vite 8 need 22.12+/22.13+.

```powershell
# 1. Install dependencies for root, backend and frontend
npm run install:all

# 2. Create the backend secret file from the template
copy backend\.env.example backend\.env          # macOS/Linux: cp backend/.env.example backend/.env

# 3. Generate a random HMAC secret and paste it into backend\.env as HMAC_SECRET=...
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

> **Database driver:** the project uses **SQLite through the `sqlite3` package** - not MySQL.
> If you ever recreate the backend from scratch: `npm uninstall mysql2` then `npm install sqlite3`
> inside `backend/`.
>
> `sqlite3` is a native module: its install script downloads a prebuilt binary for your OS.
> npm 11 only runs install scripts that are approved, so `backend/package.json` approves exactly
> this one version (`"allowScripts": { "sqlite3@6.0.1": true }`). After upgrading `sqlite3`, run
> `npm install-scripts approve sqlite3` inside `backend/` again. The warning
> `prebuild-install@7.1.3: No longer maintained` during install comes from `sqlite3` itself and is
> harmless.
>
> `backend/package.json` also contains an `overrides` entry that makes Sequelize use `uuid` 11.1.1
> instead of 8.3.2, fixing advisory GHSA-w5hq-g745-h8pq so `npm audit` reports 0 vulnerabilities.

## Run

Complete the [Setup](#setup) steps first (dependencies installed, `backend\.env` created).

| Part             | URL                                   |
| ---------------- | ------------------------------------- |
| Frontend (React) | <http://localhost:5173>  ← open this  |
| Backend (API)    | <http://127.0.0.1:4000>               |

Open exactly `http://localhost:5173` - `http://127.0.0.1:5173` is a *different origin* and the
CORS allowlist will block it.

### Option A - backend and frontend together (one terminal)

From the project root:

```powershell
npm run dev
```

Both parts start in the same terminal; output lines are prefixed `[api]` (backend) and `[web]`
(frontend). Press `Ctrl+C` once to stop both.

### Option B - backend and frontend separately (two terminals)

Start the **backend first** - the React form loads the password policy from the API, and without
it the page shows "Cannot reach the server" (click **Try again** once the backend is up).

**Terminal 1 - backend**

```powershell
npm run dev:backend          # from the project root
# or
cd backend
npm run dev                  # auto-restarts on file changes (nodemon)
npm start                    # alternative: plain node, no auto-restart
```

Ready when you see: `Communication_LTD API listening on http://127.0.0.1:4000`

**Terminal 2 - frontend**

```powershell
npm run dev:frontend         # from the project root
# or
cd frontend
npm run dev
```

Ready when you see: `Local: http://localhost:5173/` - then open that address in the browser.

Press `Ctrl+C` in each terminal to stop that part.

### Production build of the frontend (optional)

```powershell
cd frontend
npm run build                # creates frontend\dist
npm run preview              # serves the built files to check them locally
```

Note: `npm run preview` uses port 4173, which is not in the CORS allowlist. To use the API
from the preview, temporarily set `CORS_ORIGIN=http://localhost:4173` in `backend\.env` and
restart the backend.

---

## Password policy (configuration file)

The policy lives in [backend/config/password-policy.json](backend/config/password-policy.json)
and is managed by the system administrator.

| Setting            | Value | Meaning                                                        |
| ------------------ | ----- | -------------------------------------------------------------- |
| `minLength`        | 10    | Minimum password length                                        |
| `maxLength`        | 128   | Maximum length (prevents abuse with huge inputs)               |
| `complexity`       | all `true` | Require uppercase, lowercase, digits, special characters  |
| `historyCount`     | 3     | Previous passwords that may not be reused (change-password stage) |
| `dictionary`       | list  | Password may not contain any of these words (case-insensitive) |
| `maxLoginAttempts` | 3     | Failed logins before lockout (login stage)                     |

- The file is validated at startup. A wrong type or unsafe value (e.g. `minLength` below 8)
  makes the server **refuse to start** with a clear message.
- Changes apply after a restart (in development `nodemon` restarts automatically).
- The React form downloads the public part of the policy (`GET /api/auth/password-policy`), so
  the browser checklist always matches the server. The dictionary and the login-attempt limit
  are **not** sent to the browser.
- `historyCount` and `maxLoginAttempts` are already loaded and the database is ready for them
  (`password_history` table, `failed_login_attempts` / `locked_until` columns); they are
  enforced when change-password and login are implemented.

---

## API

### `GET /api/auth/password-policy`
`200` → `{ "minLength": 10, "maxLength": 128, "complexity": { ... } }`

### `POST /api/auth/register`
Body (JSON, max 10 KB): `{ "username": "...", "email": "...", "password": "..." }`

| Status | When                                                                      |
| ------ | ------------------------------------------------------------------------- |
| 201    | Created → `{ message, user: { id, username, email } }` (no salt / hash)   |
| 400    | Validation failed → `{ error, formErrors, fieldErrors }`, or malformed JSON |
| 409    | Username or email already in use (one combined message)                   |
| 429    | More than 10 registration attempts from the same IP within 15 minutes     |
| 500    | Unexpected error → generic message only                                   |

### Database tables

- **users** - `id` (UUID), `username` (unique), `email` (unique), `salt`, `password_hash`,
  `failed_login_attempts`, `locked_until`, `created_at`, `updated_at`
- **password_history** - `id` (UUID), `user_id` → users (ON DELETE CASCADE), `salt`,
  `password_hash`, `created_at`

---

## Security highlights

### 1. Password storage: HMAC-SHA256 + unique salt
[backend/src/utils/crypto.js](backend/src/utils/crypto.js)
```
salt         = crypto.randomBytes(16)                         → 32 hex chars, new for every user
passwordHash = HMAC-SHA256(key = HMAC_SECRET, msg = salt + password)  → 64 hex chars
```
- **Only `salt` and `passwordHash` are stored** - the plaintext password is never saved or logged.
- **Salt** (from Node's cryptographically secure random generator): two users with the same
  password get different hashes, and precomputed rainbow tables are useless.
- **HMAC with a secret key** (the key acts as a *pepper*): the key lives in `.env`, not in the
  database. An attacker who steals only the database file cannot even start guessing passwords
  without the key.
- **Timing-safe verification** (`crypto.timingSafeEqual`) is prepared for login, so response
  time does not reveal how much of a hash matched.
- Registration writes the user and the first `password_history` row in **one transaction**
  (both or nothing).

### 2. Secret management
- `HMAC_SECRET` is loaded from `backend/.env` with **dotenv** - never hardcoded.
- `.env` is git-ignored; only `.env.example` (no secrets) is committed.
- The environment is validated at startup: if `HMAC_SECRET` is missing or shorter than
  32 characters, the server **refuses to start**.
- Frontend `VITE_*` variables end up in browser code, so only the public API URL is placed there.

### 3. SQL injection prevention
- All database access goes through the **Sequelize ORM**, which sends values as **bound
  parameters** (prepared statements). User input is never concatenated into SQL text, so input
  such as `' OR 1=1--` is treated as plain data.
- **Allowlist validation** comes first: usernames may only contain `a-z 0-9 _`, so such payloads
  are rejected with `400` before reaching the database.
- The approach is **validate + parameterize**, not "strip dangerous characters" - stripping is
  fragile and silently changes user data.

### 4. Type confusion ("NoSQL-style" operator injection) and mass assignment
- NoSQL injection itself does not apply to SQLite, but the same trick - sending an object
  instead of a string, e.g. `{"username": {"$gt": ""}}` - is blocked: every field must be a
  **string** or the request is rejected.
- The schema is a **strict object**: unknown keys (`salt`, `passwordHash`, `isAdmin`, ...) are
  rejected, and the handler writes only explicitly listed fields. A client can never set its own
  salt, hash or privileges.

### 5. Input validation and normalization (Zod)
[backend/src/validation/userSchemas.js](backend/src/validation/userSchemas.js)
- Username and email are trimmed and lowercased, so `Admin` and `admin` cannot both register
  (SQLite `UNIQUE` is case-sensitive otherwise).
- Email format and length (max 254) are checked; the password is **never** trimmed or changed.
- Password rules come from the policy file: length, the four character classes, dictionary
  words, and "must not contain the username".
- Validation errors never echo the submitted values, so a password is never reflected back.

### 6. CORS
[backend/src/app.js](backend/src/app.js)
- An **allowlist with exactly one origin** (`CORS_ORIGIN`, the React dev server) - never `*`.
- Only `GET` / `POST` and the `Content-Type` header are allowed; no credentials.
- A request from any other website receives no `Access-Control-Allow-Origin` header, so the
  browser blocks it. Vite runs with `strictPort` so the origin cannot silently change.

### 7. HTTP hardening
- **Helmet** sets security headers (Content-Security-Policy, `X-Content-Type-Options: nosniff`,
  frame protection, HSTS) and removes `X-Powered-By`.
- **Rate limiting** on registration: 10 attempts / 15 minutes per IP → `429`.
- **Body size limit** of 10 KB and JSON-only bodies.
- The API listens on `127.0.0.1` by default, so it is not reachable from other computers.

### 8. Error handling and data minimization
- A central error handler returns short generic messages - **no stack traces, SQL or internals**.
  Details are logged on the server only. SQL logging is turned off.
- A taken username or email gives a **single combined message**, so the response does not say
  which one exists.
- The User model **hides `salt`, `passwordHash` and lockout fields by default** (default scope +
  `toJSON`); the API returns only `id`, `username`, `email`.
- Primary keys are **random UUIDs**, so user IDs cannot be guessed (1, 2, 3...).

### 9. Client-side security (React)
- React escapes all rendered text; `dangerouslySetInnerHTML` is never used → **XSS prevention**.
- Client validation (same rules, built from the server policy) improves usability only - **the
  server re-validates everything** and is the real security boundary.
- The password is **not hashed in the browser** (a client-side hash would simply become the new
  password); it is sent to the server, which hashes it.
- `autoComplete="new-password"`, confirm-password field, live policy checklist, password removed
  from memory after success, and separate messages for network, 400, 409, 429 and 500 errors.

---

## Known limitations and production notes

- **HMAC-SHA256 is a fast function.** It meets the course requirement, and the secret key adds
  strong protection, but production systems should use a deliberately slow password hash
  (**Argon2id**, scrypt or bcrypt), optionally combined with a pepper.
- **Changing `HMAC_SECRET` invalidates every stored password** - keep it safe and backed up.
- **HTTPS is mandatory in production** - the password travels in the request body.
- The rate limiter keeps its counters in memory (reset on restart, per server instance).
- `sequelize.sync()` creates missing tables only; production would use versioned migrations.
- Keep the project outside OneDrive-synced folders (e.g. `C:\dev\`): syncing can lock the SQLite
  file and slows down `node_modules`.

---

## Manual tests (PowerShell)

```powershell
$api = 'http://127.0.0.1:4000/api/auth/register'
function Register($body) {
  try { Invoke-RestMethod -Method Post -Uri $api -ContentType 'application/json' -Body $body }
  catch { $_.Exception.Response.StatusCode.value__; $_.ErrorDetails.Message }
}

Register '{"username":"dana_2","email":"dana@example.com","password":"Gr8t!Horizon#77"}'   # 201
Register '{"username":"DANA_2","email":"x@example.com","password":"Gr8t!Horizon#77"}'      # 409
Register "{`"username`":`"x' OR 1=1--`",`"email`":`"a@b.co`",`"password`":`"Gr8t!Horizon#77`"}"  # 400
Register '{"username":{"$gt":""},"email":"a@b.co","password":"Gr8t!Horizon#77"}'          # 400
Register '{"username":"eve","email":"e@b.co","password":"Gr8t!Horizon#77","salt":"00"}'   # 400
Register '{"username":"weak","email":"w@b.co","password":"MyPassword#2026"}'              # 400 (dictionary)
```

## Troubleshooting

- **`node` is not recognized** - Node is installed but the terminal started before installation:
  close *all* VS Code windows and reopen.
- **Port 5173 / 4000 already in use** - stop the other process (Vite is set to fail instead of
  switching ports, because CORS only allows port 5173).
- **CORS error in the browser** - make sure you opened `http://localhost:5173` and that
  `CORS_ORIGIN` in `backend/.env` matches it.
- **"Invalid environment configuration"** - `backend/.env` is missing or `HMAC_SECRET` is too short.
