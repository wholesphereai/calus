# Calus dashboard — build the Vite app, serve the static bundle with nginx.
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
# Origin-relative by default ("/" becomes "" in src/api.ts) so the browser calls
# same-origin and nginx reverse-proxies /api + /v1 to the proxy (see nginx.conf) —
# no CORS, no baked host. For a split-origin deploy, override at build time:
#   docker build --build-arg VITE_PROXY_URL=https://api.example.com ...
ARG VITE_PROXY_URL=/
ENV VITE_PROXY_URL=$VITE_PROXY_URL
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost/ >/dev/null 2>&1 || exit 1
