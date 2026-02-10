# frontend/edge/Dockerfile
#
# Edge nginx: serves built frontend + terminates TLS + proxies /api to the API service.
#
# Defaults are local-friendly (8080/8443). For real deployments, set QC_HTTP_PORT=80, QC_HTTPS_PORT=443.

FROM node:20-alpine AS build
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts 2>/dev/null || npm install --ignore-scripts
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
RUN apk add --no-cache openssl gettext

COPY --from=build /app/dist /usr/share/nginx/html
COPY edge/default.conf.template /etc/nginx/templates/default.conf.template
COPY edge/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /etc/nginx/certs /var/www/certbot

EXPOSE 8080 8443
ENTRYPOINT ["/entrypoint.sh"]
