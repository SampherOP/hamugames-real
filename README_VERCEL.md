# HAMUGANG — Vercel + GitHub + Neon (NO FIREBASE)

This release keeps the existing HAMUGANG HTML/game UI and uses a Vercel serverless API with Neon PostgreSQL for persistent cross-device accounts, profiles, rankings/progress, Chatter, presence, rooms and multiplayer data.

## Deploy

1. Create a free Neon PostgreSQL database and copy its connection string.
2. Push this entire folder to a GitHub repository.
3. Import the repository into Vercel.
4. In Vercel → Project → Settings → Environment Variables add:
   - `DATABASE_URL` = your Neon connection string
   - `JWT_SECRET` = a long random secret (32+ random characters)
5. Redeploy.
6. Open your Vercel HTTPS URL.

The API automatically creates the required tables on its first request. `schema.sql` is included for reference/manual setup.

## Important

- Firebase is NOT used.
- Accounts and profile data are stored in Neon, not browser localStorage only.
- The browser stores only the login token locally.
- Email is immutable after registration.
- Username is protected against duplicate claims and is treated as immutable after profile creation.
- Passwords are stored as scrypt hashes, never plaintext.
- Do NOT commit `DATABASE_URL` or `JWT_SECRET` into GitHub.
- The Vercel filesystem is not used for persistent data.

## What stays from the existing site

The existing HAMUGANG frontend, games, assets, profiles/rankings/objectives, Chatter UI and multiplayer UI are retained. The backend compatibility layer uses `/api/*` so the same HTML can run from the Vercel domain.

## Local note

This is designed for Vercel deployment. For local development, use Vercel CLI or another serverless-compatible setup with the same environment variables.
