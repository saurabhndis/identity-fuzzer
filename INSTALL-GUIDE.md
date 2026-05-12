# Identity Fuzzer — Ubuntu Installation Guide

This document contains everything needed to install and run the Identity Fuzzer
GUI on Ubuntu machines.

---

## Pre-built .deb Location

The pre-built `.deb` package is available at:

```
Machine: 10.5.19.126
Path:    ~/fuzzer-saurabh/dist/identity-fuzzer_1.0.0_amd64.deb
User:    asrivastav
```

---

## Installing on a New Ubuntu Machine

### Option A: Copy from 10.5.19.126

```bash
# From 10.5.19.126, copy the .deb to the target machine
scp ~/fuzzer-saurabh/dist/identity-fuzzer_1.0.0_amd64.deb asrivastav@<TARGET_IP>:~/

# SSH into the target machine
ssh asrivastav@<TARGET_IP>

# Install the package (handles dependencies automatically)
sudo apt install ~/identity-fuzzer_1.0.0_amd64.deb
```

### Option B: Run from source (Development Mode)

After cloning the repository, follow these steps on Ubuntu:

```bash
# 1. Install system prerequisites
sudo apt update
sudo apt install -y nodejs npm python3 python3-pip gcc build-essential \
  libgtk-3-0 libnss3 libxss1 libxtst6 libatspi2.0-0 iptables

# 2. Clone the repository
git clone <repo-url> ~/identity-fuzzer
cd ~/identity-fuzzer

# 3. Install Node.js dependencies
npm install

# 4. Compile the native DSCP addon (required for DSCP/TOS marking)
gcc -shared -fPIC -o lib/traffic/set_tos_napi.node lib/traffic/set_tos_napi.c \
  -I$(find /usr/include -name "node_api.h" -exec dirname {} \; | head -1) 2>/dev/null || \
  echo "WARNING: Could not compile DSCP addon. Install nodejs-dev: sudo apt install nodejs-dev"

# 5. Configure passwordless sudo for iptables (needed for DSCP on SYN packets)
echo "$USER ALL=(ALL) NOPASSWD: /usr/sbin/iptables" | sudo tee /etc/sudoers.d/identity-fuzzer-iptables
sudo chmod 440 /etc/sudoers.d/identity-fuzzer-iptables

# 6. Install Python dependencies for AD Simulator (optional)
pip3 install ldaptor twisted pydantic cryptography click

# 7. Launch the app
npx electron . --no-sandbox
```

### Option C: Build .deb package from source

```bash
# Clone or copy the project
git clone <repo-url> ~/identity-fuzzer
cd ~/identity-fuzzer

# Install Node.js dependencies
npm install

# Build the .deb package
npm run dist:deb

# Install the built package
sudo apt install ./dist/identity-fuzzer_1.0.0_amd64.deb
```

The `.deb` post-install script automatically:
- Configures passwordless sudo for iptables
- Compiles the native DSCP addon
- Installs Python dependencies for AD Simulator
- Sets chrome-sandbox permissions

---

## Prerequisites on Target Machine

### For running from source (Option B):

| Package | Purpose | Install Command |
|---------|---------|-----------------|
| `nodejs` (≥18) | Electron runtime | `sudo apt install nodejs npm` |
| `python3` | AD Simulator | `sudo apt install python3 python3-pip` |
| `gcc`, `build-essential` | Compile DSCP addon | `sudo apt install gcc build-essential` |
| `nodejs-dev` | Node.js headers for addon | `sudo apt install nodejs-dev` |
| `iptables` | DSCP marking on SYN packets | `sudo apt install iptables` |

### For .deb package install (Options A/C):

The `.deb` package automatically installs these dependencies:

- `libgtk-3-0`, `libnotify4`, `libnss3`, `libxss1`, `libxtst6`
- `xdg-utils`, `libatspi2.0-0`, `libuuid1`, `libsecret-1-0`
- `python3`, `python3-pip`

---

## Launching the App

### From the Desktop (GUI)

1. Open your application menu / Activities
2. Search for **"Identity Fuzzer"**
3. Click the icon to launch

> **Note:** After first install, you may need to log out and log back in for
> the app to appear in the application menu.

### From Terminal

```bash
# Standard launch
identity-fuzzer --no-sandbox

# If you get display errors via SSH, use:
export DISPLAY=:10.0
export XAUTHORITY=$(ls /run/user/$(id -u)/.mutter-Xwaylandauth.* 2>/dev/null | head -1)
identity-fuzzer --no-sandbox --ozone-platform-hint=auto
```

### The `--no-sandbox` Flag

The `--no-sandbox` flag is needed because the Electron chrome-sandbox requires
root SUID bit. To avoid needing this flag, run:

```bash
sudo chown root:root /opt/Identity\ Fuzzer/chrome-sandbox
sudo chmod 4755 /opt/Identity\ Fuzzer/chrome-sandbox
```

After that, you can launch without `--no-sandbox`:

```bash
identity-fuzzer
```

---

## Uninstalling

```bash
sudo apt remove identity-fuzzer
# Or to also remove config:
sudo apt purge identity-fuzzer
```

---

## Deployment Status

| Machine | IP | Status | Notes |
|---------|----|--------|-------|
| Lab Machine 1 | 10.5.19.126 | ✅ Installed & Running | Installed 2026-05-11, Python deps vendored via postinst |
| Lab Machine 2 | 10.5.17.106 | ✅ Installed & Running | Installed 2026-05-11, Python deps vendored via postinst |
| Lab Machine 3 | 10.5.15.106 | ❌ Pending | Machine unreachable (down). Use instructions above when available |

---

## Troubleshooting

### App doesn't appear in application menu

```bash
# Refresh the desktop database
sudo update-desktop-database /usr/share/applications
# Log out and log back in
```

### GPU errors in log (vaInitialize, ContextResult)

These are non-fatal warnings common in VM environments. The app works fine
despite these messages. To suppress them:

```bash
identity-fuzzer --no-sandbox --disable-gpu
```

### "No space left on device" during build

The build needs ~800MB free. Clean up space:

```bash
sudo apt-get clean
pip3 cache purge
rm -rf ~/.cache/electron ~/.cache/electron-builder
```

Or build with `SKIP_PYTHON_VENDOR=1` to save ~100MB (Python deps will be
installed during package installation instead).

### Display errors when launching via SSH

Electron needs access to the display server. When launching via SSH:

```bash
# For Wayland sessions (Ubuntu 22.04+)
export DISPLAY=:10.0
export XAUTHORITY=$(ls /run/user/$(id -u)/.mutter-Xwaylandauth.* 2>/dev/null | head -1)
identity-fuzzer --no-sandbox --ozone-platform-hint=auto

# For X11 sessions
export DISPLAY=:0
identity-fuzzer --no-sandbox
```

### Missing Python dependencies for AD Simulator

If the AD Simulator tab doesn't work:

```bash
pip3 install ldaptor twisted pydantic cryptography click
```

---

## Package Details

```
Package:      identity-fuzzer
Version:      1.0.0
Architecture: amd64
Install Path: /opt/Identity Fuzzer/
Binary:       /usr/bin/identity-fuzzer
Desktop File: /usr/share/applications/identity-fuzzer.desktop
Config Dir:   ~/.config/identity-fuzzer/
```
