# LEDGERLY

Shared ledger app (tea, snacks, travel) with member balances.

- `public/ledgerly.html` is the front end.
- `server.js` is the API (Node + Express + MongoDB).

## Run locally
1. Copy `.env.example` to `.env` and fill in `MONGO_URI` and `JWT_SECRET`.
2. `npm install`
3. `npm start`, then open http://localhost:3000/ledgerly.html
4. On first launch, create the admin account.
