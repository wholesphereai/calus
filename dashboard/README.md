# Calus Dashboard

A React + TypeScript console for the [Calus proxy](../). It shows live detection
traffic: stats, a 24-hour traffic chart, an OWASP threat breakdown, and a
searchable feed of every scanned call with a detail drawer. Dark by default, with
a light toggle. No chart library — charts are hand-drawn SVG, so there are no
extra dependencies to break.

## Run it

```bash
npm install
cp .env.example .env        # set VITE_PROXY_URL if the proxy isn't on :8000
npm run dev                 # opens http://localhost:5173
```

On first load it asks for your **admin token** — the `CALUS_ADMIN_TOKEN` the proxy
printed at startup. It's stored in your browser and sent as `X-Admin-Token`.

## Build for production

```bash
npm run build               # type-checks then outputs static files to dist/
npm run preview             # serve the build locally
```

Serve `dist/` from any static host. Make sure the proxy's `CALUS_CORS_ORIGINS`
includes wherever you serve the dashboard from.

## Config

| Variable | Default | Purpose |
|---|---|---|
| `VITE_PROXY_URL` | `http://localhost:8000` | where the Calus proxy is running |
