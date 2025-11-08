# ---------- 1. Build Angular frontend ----------
FROM node:20-alpine AS fe
WORKDIR /app

COPY frontend/package*.json ./
RUN npm install --legacy-peer-deps

COPY frontend/ ./
RUN npm run build -- --configuration production --output-path=dist

# ---------- 2. Build Go backend ----------
FROM golang:1.25-alpine AS be
WORKDIR /app

COPY backend/ ./
RUN go build -o server main.go

# ---------- 3. Final runtime image ----------
FROM alpine:3.19

RUN apk add --no-cache nginx ca-certificates && \
    mkdir -p /run/nginx /usr/share/nginx/html /var/lib/nginx/tmp /var/log/nginx && \
    adduser -D -g 'www' www

# Copy built frontend and backend
COPY --from=fe /app/dist/ /usr/share/nginx/html/
COPY --from=be /app/server /server
COPY nginx.conf /etc/nginx/nginx.conf
RUN chown -R www:www /usr/share/nginx/html /var/lib/nginx /run/nginx /var/log/nginx && \
    chmod -R 755 /usr/share/nginx/html /var/lib/nginx /run/nginx /var/log/nginx

EXPOSE 8080
USER www
CMD /server & nginx -g 'daemon off;'