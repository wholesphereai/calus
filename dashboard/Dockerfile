# Calus dashboard — build the Vite app, serve the static bundle with nginx.
FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
# VITE_PROXY_URL can be overridden at build time; defaults to localhost:8000,
# which is correct when the browser reaches the proxy on the host.
ARG VITE_PROXY_URL
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
