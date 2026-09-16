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

ARG SOURCE_DATE_EPOCH=1735689600

FROM ghcr.io/m1k1o/neko/base@sha256:4de36f83b563c7aa4bcc7a4e357609b95eb09be91c106244fc6e0ea00b789cb5

ARG SOURCE_DATE_EPOCH

# Install the exact Chrome artifact recorded in the signed SBOM for the
# reviewed operator release. Verify the official package-index SHA-256 before
# asking apt to resolve its runtime dependencies.  A version/checksum change is
# a reviewed source change and requires a fresh image digest and attestations.
RUN set -eux; \
    sed -ri \
      's|^URIs: http://deb.debian.org/debian$|URIs: https://snapshot.debian.org/archive/debian/20260406T000000Z|; s|^URIs: http://deb.debian.org/debian-security$|URIs: https://snapshot.debian.org/archive/debian-security/20260406T000000Z|' \
      /etc/apt/sources.list.d/debian.sources; \
    apt-get -o Acquire::Check-Valid-Until=false update; \
    wget -O /tmp/google-chrome.deb \
      "https://dl.google.com/linux/chrome/deb/pool/main/g/google-chrome-stable/google-chrome-stable_150.0.7871.114-1_amd64.deb"; \
    echo "0f19e68dca574849632e25229f15853d2beac33fa06498feed43f34628bc2d53  /tmp/google-chrome.deb" \
      | sha256sum -c -; \
    apt-get install -y --no-install-recommends \
      openbox=3.6.1-12+b2 \
      nginx=1.26.3-3+deb13u2 \
      /tmp/google-chrome.deb; \
    rm -f /tmp/google-chrome.deb; \
    apt-get clean -y; \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/* /var/cache/ldconfig/* /var/log/apt/*; \
    rm -f /var/log/dpkg.log /var/log/alternatives.log

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
