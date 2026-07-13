# Custom neko + Google Chrome + CDP remote debugging
#
# Based on upstream m1k1o/neko google-chrome but with:
#   - CDP remote debugging enabled (port 9223)
#   - Nginx CDP proxy built-in (port 9222)
#   - Policies tuned for TEE automation (no sign-in, no extensions)
#
# Google Chrome only ships amd64 Linux .deb packages.
# On Apple Silicon Macs, this runs via OrbStack/Rosetta emulation.
# On Phala Cloud (amd64 Intel TDX), this runs natively.

FROM ghcr.io/m1k1o/neko/base@sha256:4de36f83b563c7aa4bcc7a4e357609b95eb09be91c106244fc6e0ea00b789cb5

# Install Google Chrome stable (amd64 only)
RUN set -eux; \
    apt-get update; \
    wget -O /tmp/google-chrome.deb \
      "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"; \
    apt-get install -y --no-install-recommends \
      openbox \
      nginx \
      /tmp/google-chrome.deb; \
    rm -f /tmp/google-chrome.deb; \
    apt-get clean -y; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Chrome supervisord config — CDP remote debugging enabled
COPY supervisord.conf /etc/neko/supervisord/google-chrome.conf

# Chrome preferences — minimal, no first-run
COPY --chown=neko preferences.json /home/neko/.config/chrome-cdp/Default/Preferences

# Chrome policies — lock down for automation
COPY policies.json /etc/opt/chrome/policies/managed/policies.json

# Openbox config — no decorations, maximized
COPY openbox.xml /etc/neko/openbox.xml

# Nginx CDP proxy config — proxy 9222 → Chrome's 9223
COPY nginx-cdp.conf /etc/nginx/conf.d/cdp.conf
RUN rm -f /etc/nginx/sites-enabled/default

EXPOSE 8080 9222
