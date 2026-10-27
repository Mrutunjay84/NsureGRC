# nsuregrc-ui

React + TypeScript + Tailwind + shadcn/ui frontend for NsureGRC (D-P6-001), living inside the same repo as
the Django backend (`03_APP/nsuregrc/nsuregrc-ui`). Dev-proxied to the backend so the existing cookie-session
+ CSRF auth works unmodified - no CORS, no token storage. See `00_CONTROL/PHASE6/` for the decisions behind
this.

## Local setup (one time)

From the repo root (`03_APP/nsuregrc`, one level up from this folder):

```bash
bash scripts/gen_dev_cert.sh              # self-signed cert for the dev server, .dev-certs/ (gitignored)
NGRC_PLANE=all uv run python manage.py dev_seed_tenant --slug devco   # creates an owner account, no MFA yet
```

The seed command prints the account's email/password. There is no self-service signup anywhere in this
application - this command exists only because local UI development needs a first account to log in with.
Log in through the UI; the login screen's MFA-enrollment step is the real one (no pre-enrollment, no
skipping it - the backend requires TOTP for every customer account).

## Running it

Two processes:

```bash
# terminal 1 - backend, HTTPS on 127.0.0.1:8443, from the repo root (03_APP/nsuregrc)
uv run python scripts/dev_run_https.py

# terminal 2 - frontend, HTTPS on localhost:5173, proxies /api and /healthz to the backend, from this folder
npm install   # first time only
npm run dev
```

Open `https://localhost:5173`. The backend cert is self-signed, so the browser will warn once -
`scripts/dev_run_https.py`'s docstring explains why `gunicorn` (the real production server) isn't used here
(it doesn't run on Windows) and why it's `wsgiref`-based rather than `uvicorn` (uvicorn's `h11` layer rejects
a Set-Cookie header Django itself always produces with a leading space - confirmed while standing this up,
not hypothetical).

## Scripts

- `npm run dev` - Vite dev server
- `npm run build` - typecheck (`tsc -b`) + production build
- `npm run lint` - oxlint
