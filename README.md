# GuardianScan

Personal cybersecurity assistant — check if your email, password, phone, username, IP, or domain has appeared in known data breaches.

## Quick Start

```bash
npm install
node server.js
```

Then open http://localhost:3000

## Requirements

- Node.js 18 or newer (uses built-in `fetch`)
- Internet connection (queries external breach APIs)

## What it checks

| Type | Sources |
|------|---------|
| Email | LeakCheck.io · BreachDirectory · emailrep.io · HIBP catalog |
| Password | HIBP k-anonymity (14B+ records, your password is never sent in full) |
| Phone | LeakCheck.io · BreachDirectory · HIBP catalog |
| Username | LeakCheck.io · BreachDirectory · HIBP catalog |
| IP Address | LeakCheck.io · BreachDirectory · HIBP catalog |
| Domain | HIBP catalog (exact match) + LeakCheck.io |

## Files

```
server.js      Express API server + static file hosting
index.html     Full React frontend (no build step needed — uses CDN)
package.json   Single dependency: express
.gitignore     Ignores node_modules and .env
README.md      This file
```

## Deploy anywhere

Works on Render, Railway, Fly.io, Heroku, or any VPS:

```bash
npm install
PORT=8080 node server.js
```

No database required. No API keys required. Completely free to run.
