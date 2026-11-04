FROM debian:bookworm-slim

ARG XRAY_VERSION=v26.10.31
ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive \
    HOME=/root \
    L2XPANEL_DATA=/var/lib/l2xpanel \
    XRAY_CONFIG=/etc/xray/config.json \
    XRAY_LOCATION_ASSET=/usr/local/share/xray \
    PANEL_PORT=2053 \
    PANEL_ADMIN_USER=admin \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-venv ca-certificates curl unzip openssl socat procps cron \
      iproute2 iptables iputils-ping kmod ppp xl2tpd strongswan strongswan-starter \
      libstrongswan-standard-plugins wireguard-tools supervisor \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      arm64) asset=Xray-linux-arm64-v8a.zip ;; \
      arm) asset=Xray-linux-arm32-v7a.zip ;; \
      *) asset=Xray-linux-64.zip ;; \
    esac; \
    curl -fsSL -o /tmp/xray.zip "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${asset}"; \
    mkdir -p /usr/local/share/xray /etc/xray /var/log/xray; \
    unzip -o /tmp/xray.zip xray geoip.dat geosite.dat -d /tmp/xray; \
    install -m 755 /tmp/xray/xray /usr/local/bin/xray; \
    mv /tmp/xray/*.dat /usr/local/share/xray/; \
    rm -rf /tmp/xray /tmp/xray.zip; \
    /usr/local/bin/xray version

WORKDIR /opt/l2xpanel
COPY panel/requirements.txt .
RUN python3 -m venv .venv && .venv/bin/pip install --no-cache-dir -r requirements.txt

COPY panel/ ./
COPY scripts/l2x.sh /usr/local/bin/l2x
COPY deploy/ipsec.conf /etc/ipsec.conf
COPY deploy/xl2tpd.conf /etc/xl2tpd/xl2tpd.conf
COPY docker/systemctl docker/journalctl /usr/local/bin/
COPY docker/supervisord.conf /etc/supervisor/conf.d/l2x.conf
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /usr/local/bin/l2x /usr/local/bin/systemctl /usr/local/bin/journalctl /entrypoint.sh

VOLUME ["/var/lib/l2xpanel", "/etc/l2xpanel"]
HEALTHCHECK --interval=30s --timeout=5s CMD curl -fsS "http://127.0.0.1:${PANEL_PORT}/health" || exit 1
ENTRYPOINT ["/entrypoint.sh"]
