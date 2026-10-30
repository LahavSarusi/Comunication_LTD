# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Cybersecurity course final project: a web system for the fictional ISP "Communication_LTD". The emphasis is secure development. JavaScript only: React (Vite) frontend, Express 5 + Sequelize + SQLite backend. Part A (user registration) is implemented. The database schema already supports the next stages: login with lockout, change password with history, forgot password, and a "system" screen for clients. `README.md` contains the "Security highlights" section that is submitted for grading, so update it whenever a security control is added or changed.

## Commands

Run from the repo root unless noted. Paths contain Hebrew characters and spaces (OneDrive Desktop), so always quote them.

```powershell
npm run install:all    # npm install in root, backend/ and frontend/
npm run dev            # backend (nodemon, :4000) + frontend (vite, :5173) via concurrently
npm run dev:backend    # or: npm --prefix backend run dev   (start = plain node index.js)
npm run dev:frontend
npm --prefix frontend run lint
npm --prefix frontend run build
```

- There is no automated test suite. Verify by running the API and calling it. The README's "Manual tests (PowerShell)" section lists requests for valid, duplicate, SQLi, `{"$gt":""}`, extra-field and dictionary cases.
- The registration rate limiter (10 requests / 15 min / IP, in memory) returns 429 during heavy testing. Restarting the backend resets it.
- Backend requires `backend/.env` (template: `backend/.env.example`). The frontend `.env` is optional; `VITE_API_URL` defaults to `http://127.0.0.1:4000`.

## Architecture

Two independent npm projects, `backend/` (CommonJS, semicolons) and `frontend/` (ESM, no semicolons, Vite template style). There are no npm workspaces; the root `package.json` only holds `concurrently` and scripts.

**Fail-fast config.** `backend/src/config/env.js` and `backend/src/config/passwordPolicy.js` validate with Zod when first required and call `process.exit(1)` on bad input. `index.js` requires them before anything else. A missing or short `HMAC_SECRET`, or an invalid policy file, means the server will not boot.

**Password policy is a single source of truth.** The chain is:
1. `backend/config/password-policy.json` is the admin-editable file (length, complexity, `historyCount`, dictionary, `maxLoginAttempts`).
2. `passwordPolicy.js` validates and deep-freezes it, and exports `policy` and `publicPolicy`.
3. `validation/userSchemas.js` builds the server Zod schema from `policy`.
4. `GET /api/auth/password-policy` returns only `publicPolicy` (min/max length, complexity).
5. `frontend/src/validation/registerSchema.js` builds a matching client schema and the live checklist from it.

The dictionary and `maxLoginAttempts` deliberately stay server-only. The special-character regex and username pattern are duplicated in both validation files; keep them in sync. nodemon restarts the backend when the policy JSON changes.

**Request pipeline** (`backend/src/app.js` → `routes/auth.routes.js`):
1. `helmet`
2. `cors` with `origin: [CORS_ORIGIN]` as an array, so a non-matching origin gets no ACAO header
3. `express.json({ limit: '10kb' })`
4. per-route `rateLimit`
5. `validate(schema)` (`middleware/validate.js`), which stores parsed, normalized data on **`req.validatedBody`**. Handlers must read that, not `req.body`.
6. the handler
7. `middleware/errorHandler.js`: `UniqueConstraintError` → 409 with one combined username/email message; body-parser 4xx → generic 400/413; everything else → generic 500 with no details. Express 5 forwards async handler rejections automatically.

**Validation conventions.** Schemas use `z.strictObject` (rejects unknown keys, i.e. mass assignment) and accept only strings (rejects operator objects). Username and email are trimmed and lowercased, and usernames must match `^[a-z0-9_]{3,30}$`. Passwords are never trimmed or modified. The approach is allowlist + ORM bound parameters, not character stripping.

**Password hashing** (`backend/src/utils/crypto.js`): a 16-byte random salt as hex, then `HMAC-SHA256(key = HMAC_SECRET, msg = salt + password)` as hex. The course mandates HMAC + salt, so don't swap in bcrypt/argon2 without the user's agreement. `verifyPassword()` (timing-safe) exists for the future login. Changing `HMAC_SECRET` invalidates all stored hashes.

**Models** (`backend/src/models/`, wired in `models/index.js`):
- Tables are `users` and `password_history` (`underscored: true`), with UUID primary keys.
- `User`'s `defaultScope` excludes `salt`, `passwordHash`, `failedLoginAttempts` and `lockedUntil`; `toJSON` strips them too. Login code must use `User.scope('withCredentials')`. API responses list fields explicitly.
- Registration creates the `User` and its first `PasswordHistory` row inside one `sequelize.transaction`.
- Schema is created by `sequelize.sync()` (no migrations), so changing a model does not alter an existing table. In development, delete `backend/data/database.sqlite` (git-ignored, recreated on start) after schema changes.

**Ports and origins.** The API binds to `HOST`/`PORT` from `.env` (`127.0.0.1:4000`). Vite uses port 5173 with `strictPort: true` because it must equal `CORS_ORIGIN=http://localhost:5173`. Opening the app at `127.0.0.1:5173` is a different origin and gets blocked.

**Frontend.** `src/api/client.js` holds the axios instance and `parseApiError()`, which maps network errors and 400/409/429/5xx to user messages plus `fieldErrors`. `components/Register/Register.jsx` fetches the policy on mount, validates client-side and submits. Render all server text as JSX text; never use `dangerouslySetInnerHTML`.

## Environment gotchas (Windows)

- Node lives in `C:\Program Files\nodejs`. A shell started before Node was installed may lack it on PATH. In Bash, prefix commands with `export PATH="/c/Program Files/nodejs:$PATH";`. The minimum is Node 22.13 (root `engines`).
- npm 11 runs install scripts only when they are approved. `backend/package.json` approves `"sqlite3@6.0.1": true`; its install script downloads the native binary, so a deny breaks clean installs. Re-run `npm install-scripts approve sqlite3` in `backend/` after upgrading sqlite3.
- `backend/package.json` `overrides` pins Sequelize's `uuid` to `^11.1.1` (audit fix GHSA-w5hq-g745-h8pq). Keep it until Sequelize ships a fixed version.
- Stopping a background `npm run dev` kills only the shell; child `node` processes (vite, nodemon) keep ports 4000/5173 and cause "Port 5173 is already in use". After any test run, check `netstat -ano | findstr ":4000 :5173"` and stop leftovers by their verified PID, never the user's own dev processes. Prefer `node index.js` directly for backend tests.
