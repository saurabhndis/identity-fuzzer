# Building Identity Fuzzer for Ubuntu (.deb package)

This guide explains how to build a `.deb` package for Ubuntu/Debian so you can
install and launch the Identity Fuzzer GUI on those machines.

---

## Prerequisites

### On the build machine (macOS or Linux)

| Tool | Version | Purpose |
|------|---------|---------|
| **Node.js** | ≥ 18 | Runtime & npm |
| **Python 3** | ≥ 3.9 | AD Simulator dependencies |
| **Docker** *(optional)* | latest | Cross-compile from macOS → Linux |

> **Note:** Building a `.deb` natively requires a Linux (x64) machine or Docker.
> If you are on macOS, electron-builder will use Docker automatically to produce
> the Linux package.

### On the target Ubuntu machine

The `.deb` package declares these dependencies automatically:

- `libgtk-3-0`, `libnotify4`, `libnss3`, `libxss1`, `libxtst6`
- `xdg-utils`, `libatspi2.0-0`, `libuuid1`, `libsecret-1-0`
- `python3`, `python3-pip`

---

## Quick Build

```bash
# 1. Install Node dependencies (including electron-builder)
npm install

# 2. Generate the app icon (only needed once)
npm run generate-icon

# 3. Build the .deb package
npm run dist:deb
```

The output `.deb` file will be in the `dist/` directory.

---

## Build Commands

| Command | Description |
|---------|-------------|
| `npm run dist` | Build `.deb` package (default Linux target) |
| `npm run dist:deb` | Build `.deb` package explicitly |
| `npm run dist:appimage` | Build `.AppImage` (portable, no install needed) |
| `npm run dist:all-linux` | Build both `.deb` and `.AppImage` |
| `npm run pack` | Pack without creating installer (for testing) |

---

## Cross-compiling from macOS

If you're building on macOS, electron-builder needs Docker to create Linux
packages. Make sure Docker Desktop is running, then:

```bash
npm run dist:deb
```

electron-builder will automatically pull the required Docker image and build
inside a Linux container.

---

## Installing on Ubuntu

```bash
# Install the .deb package
sudo dpkg -i dist/identity-fuzzer_1.0.0_amd64.deb

# Fix any missing dependencies
sudo apt-get install -f

# Or install directly with apt (handles dependencies automatically)
sudo apt install ./dist/identity-fuzzer_1.0.0_amd64.deb
```

---

## Launching the App

After installation, you can launch Identity Fuzzer in three ways:

1. **Application Menu** — Search for "Identity Fuzzer" in your desktop
   environment's application launcher.

2. **Terminal** — Run:
   ```bash
   identity-fuzzer
   ```

3. **Direct binary** — Run:
   ```bash
   /opt/Identity\ Fuzzer/identity-fuzzer
   ```

---

## Uninstalling

```bash
sudo apt remove identity-fuzzer
# or to also remove config:
sudo apt purge identity-fuzzer
```

---

## AD Simulator Python Dependencies

The AD Simulator module requires Python packages (`ldaptor`, `twisted`,
`pydantic`, `cryptography`, `click`). The build process attempts to vendor
these into the package automatically via the `afterPack` hook.

If the vendored install fails during build, the post-install script will
attempt to install them on the target machine. If that also fails, install
manually:

```bash
pip3 install ldaptor twisted pydantic cryptography click
```

---

## Troubleshooting

### "electron-builder: command not found"

Make sure you ran `npm install` first. electron-builder is installed as a dev
dependency.

### Sandbox errors on launch

If you see Chrome sandbox errors, either:

```bash
# Option A: Fix sandbox permissions (the postinst script does this)
sudo chown root:root /opt/Identity\ Fuzzer/chrome-sandbox
sudo chmod 4755 /opt/Identity\ Fuzzer/chrome-sandbox

# Option B: Launch with --no-sandbox
identity-fuzzer --no-sandbox
```

### Docker not found (macOS cross-compile)

Install Docker Desktop from https://www.docker.com/products/docker-desktop/
and make sure it's running before building.

### Missing libgtk / display errors

Make sure you have a display server running (X11 or Wayland). On a headless
server, you'll need Xvfb:

```bash
sudo apt install xvfb
xvfb-run identity-fuzzer
```

---

## Project Structure (Build Files)

```
build/
├── icon.png              # App icon (512×512 PNG)
├── generate-icon.js      # Script to regenerate the icon
├── afterPack.js          # electron-builder hook: vendors Python deps
└── deb-scripts/
    ├── postinst.sh       # Runs after .deb install
    └── postrm.sh         # Runs after .deb removal
```
