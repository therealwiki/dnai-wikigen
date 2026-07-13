# neko-chrome — Custom Neko + Google Chrome + CDP

Custom [m1k1o/neko](https://github.com/m1k1o/neko) image with Google Chrome
stable and Chrome DevTools Protocol (CDP) remote debugging baked in.

## Why custom?

The upstream `m1k1o/neko:google-chrome` image does not expose CDP. We need
CDP for playwright/puppeteer automation from other containers (e.g. the
email oracle's browser fallback signup). This image adds:

- **CDP remote debugging** on port 9223 (Chrome) proxied via nginx on 9222
- **Nginx CDP proxy** built into the container (no separate sidecar needed)
- **Automation-tuned Chrome flags** — no throttling, no backgrounding, DevTools forced available
- **Locked-down policies** — no sign-in, no autofill, no extensions

## Architecture note: amd64 only

Google Chrome only ships `amd64` Linux `.deb` packages. There is no ARM64
Linux build of Google Chrome (Chrome for Testing also lacks `linux-arm64`).

| Environment | How it runs |
|------------|-------------|
| **macOS Apple Silicon** | amd64 via OrbStack Rosetta emulation (fast, transparent) |
| **Phala Cloud (Intel TDX)** | Native amd64 (no emulation) |
| **Any x86_64 Linux** | Native amd64 |

The `docker-compose.yaml` sets `platform: linux/amd64` so Docker/OrbStack
handles the emulation automatically on ARM hosts.

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 8080 | HTTP/WebSocket | Neko web UI (WebRTC browser viewer) |
| 9222 | HTTP/WebSocket | CDP proxy (nginx → Chrome's 9223) |

## Connecting via CDP

From another container on the same docker network:

```python
from playwright.async_api import async_playwright

async with async_playwright() as p:
    browser = await p.chromium.connect_over_cdp("http://neko:9222")
    page = await browser.contexts[0].new_page()
    await page.goto("https://example.com")
```

From the host machine:

```python
browser = await p.chromium.connect_over_cdp("http://localhost:9222")
```

Or via raw CDP:

```bash
# Get browser websocket URL
curl http://localhost:9222/json/version

# List open tabs/targets
curl http://localhost:9222/json/list
```

## Key files

| File | Purpose |
|------|---------|
| `Dockerfile` | Builds on `ghcr.io/m1k1o/neko/base`, installs Chrome + nginx |
| `supervisord.conf` | Chrome launch flags (CDP enabled) + openbox + nginx |
| `nginx-cdp.conf` | Reverse proxy: 9222 → Chrome's internal 9223 (WebSocket) |
| `preferences.json` | Chrome profile: no first-run, no sign-in prompts |
| `policies.json` | Chrome enterprise policies: no autofill, no extensions |
| `openbox.xml` | Window manager: no decorations, maximized Chrome |

## Chrome flags explained

```
--user-data-dir=/home/neko/.config/chrome-cdp
```
**Must be a non-default path.** Chrome refuses to enable remote debugging if
`--user-data-dir` points to the standard `~/.config/google-chrome` directory.
This was the hardest gotcha to debug — Chrome silently prints
"DevTools remote debugging requires a non-default data directory" and skips
binding the debug port.

```
--remote-debugging-port=9223
--remote-debugging-address=0.0.0.0
--remote-allow-origins=*
```
Enable CDP on port 9223, bind all interfaces, allow any origin (needed for
nginx proxy and cross-container access).

```
--enable-automation
--disable-background-timer-throttling
--disable-backgrounding-occluded-windows
--disable-renderer-backgrounding
--force-devtools-available
```
Prevent Chrome from throttling background tabs or hiding DevTools. Essential
for headful automation where the browser window may not be focused.

```
--disable-features=TranslateUI,VizDisplayCompositor
--disable-ipc-flooding-protection
--enable-blink-features=IdleDetection
```
Suppress translation popups, prevent IPC flood disconnects during automation,
enable idle detection API.

## Building

```bash
# From the tee-email-oracle directory
docker compose --profile browser build neko

# Or standalone
cd neko-chrome && docker build -t neko-chrome .
```

## Running standalone (without oracle)

```bash
docker run -d \
  --name neko-chrome \
  --platform linux/amd64 \
  --shm-size 2gb \
  --cap-add SYS_ADMIN \
  -p 52000:8080 \
  -p 9222:9222 \
  -e NEKO_SCREEN=1920x1080@30 \
  -e NEKO_PASSWORD=neko \
  -e NEKO_PASSWORD_ADMIN=admin \
  -e NEKO_ICELITE=0 \
  neko-chrome

# View browser: http://localhost:52000  (password: admin)
# CDP endpoint: http://localhost:9222
```

## Upstream references

- [m1k1o/neko](https://github.com/m1k1o/neko) — base project
- [m1k1o/neko google-chrome Dockerfile](https://github.com/m1k1o/neko/tree/master/apps/google-chrome) — upstream Chrome variant we forked from
- [amiller/neko-with-playwright](https://github.com/AcountLink/neko-with-playwright) — CDP proxy pattern via nginx (our nginx config derives from this)
