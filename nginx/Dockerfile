FROM golang:1.26.8-bookworm AS tls-edge-builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/frontiercloud-tls-edge ./cmd/frontiercloud-tls-edge
COPY internal/certedge ./internal/certedge
COPY internal/filelease ./internal/filelease
RUN GOMEMLIMIT=600MiB GOGC=25 GOMAXPROCS=2 CGO_ENABLED=0 go build -p=1 -trimpath -ldflags="-s -w" -o /tls-edge ./cmd/frontiercloud-tls-edge

FROM nginx:1.30.4-alpine AS traffic-module-builder
RUN apk add --no-cache build-base curl pcre2-dev openssl-dev zlib-dev linux-headers
COPY nginx/traffic /module
WORKDIR /build
RUN curl -fsSL https://nginx.org/download/nginx-1.30.4.tar.gz -o nginx.tar.gz && \
    echo "4261dc90e9e47c1c4041276e9aaa3d48ebe2e664f728e14fa95ae6c67d57a08b  nginx.tar.gz" | sha256sum -c - && \
    tar -xzf nginx.tar.gz && cd nginx-1.30.4 && \
    ./configure --with-compat --with-http_ssl_module --with-http_v2_module --add-dynamic-module=/module && \
    make -j2 modules && test -s objs/ngx_http_fc_traffic_module.so

FROM nginx:1.30.4-alpine

ARG REVISION
ARG FRONTIERCLOUD_RUNTIME=go
LABEL frontiercloud.revision=$REVISION frontiercloud.component="nginx" \
      frontiercloud.runtime=$FRONTIERCLOUD_RUNTIME frontiercloud.schema-generation="7" frontiercloud.automatic-tls="1"

# Remove the bundled default server.
RUN rm /etc/nginx/conf.d/default.conf

# Read finalized private recordings through internal authenticated locations.
# This group matches the native volume owner; the worker keeps its own UID.
RUN addgroup -g 10001 frontiercloud-media

# Keep runtime environment substitution in Nginx templates. Avoid BuildKit-only
# COPY --chmod for compatibility with the bounded development build driver.
COPY nginx/nginx.conf /etc/nginx/templates/nginx.conf.template
COPY --from=traffic-module-builder /build/nginx-1.30.4/objs/ngx_http_fc_traffic_module.so /usr/lib/nginx/modules/
COPY nginx/15-select-tls.sh /docker-entrypoint.d/15-select-tls.sh
COPY nginx/19-maintenance-gate.sh /docker-entrypoint.d/19-maintenance-gate.sh
COPY nginx/25-ip-security.sh /docker-entrypoint.d/25-ip-security.sh
COPY nginx/22-automatic-tls.sh /docker-entrypoint.d/22-automatic-tls.sh
COPY nginx/26-automatic-tls.sh /docker-entrypoint.d/26-automatic-tls.sh
COPY --from=tls-edge-builder /tls-edge /usr/local/bin/frontiercloud-tls-edge
COPY nginx/render-security.awk /etc/nginx/render-security.awk
COPY nginx/security-headers.conf /etc/nginx/security-headers.conf
COPY nginx/proxy-response-headers.conf /etc/nginx/proxy-response-headers.conf
COPY nginx/karaoke-security-headers.conf /etc/nginx/karaoke-security-headers.conf
COPY nginx/maintenance-gate.conf /etc/nginx/maintenance-gate.conf
COPY nginx/maintenance.html /usr/share/nginx/html/maintenance.html
COPY nginx/transport /etc/nginx/transport
COPY static /app/static
RUN chmod 0755 \
        /docker-entrypoint.d/15-select-tls.sh \
        /docker-entrypoint.d/19-maintenance-gate.sh \
        /docker-entrypoint.d/22-automatic-tls.sh \
        /docker-entrypoint.d/26-automatic-tls.sh \
        /docker-entrypoint.d/25-ip-security.sh && \
    chmod -R a+rX /app/static /usr/share/nginx/html/maintenance.html

RUN mkdir -p /run/frontiercloud-traffic && chmod 0755 /run/frontiercloud-traffic

EXPOSE 80 443

CMD ["nginx", "-g", "daemon off;"]
