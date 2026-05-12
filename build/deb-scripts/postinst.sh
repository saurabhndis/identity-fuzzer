#!/bin/bash
# Post-installation script for Identity Fuzzer .deb package

set -e

APP_DIR="/opt/Identity Fuzzer"
VENDOR_DIR="$APP_DIR/resources/app.asar.unpacked/lib/ad-simulator/vendor"
REQUIREMENTS="$APP_DIR/resources/app.asar.unpacked/lib/ad-simulator/requirements.txt"

# Install Python dependencies if not already vendored during build
if [ -f "$REQUIREMENTS" ] && [ ! -d "$VENDOR_DIR" ]; then
    echo "Installing Python dependencies for AD Simulator..."
    mkdir -p "$VENDOR_DIR"
    python3 -m pip install --target "$VENDOR_DIR" -r "$REQUIREMENTS" --no-cache-dir 2>/dev/null || {
        echo "WARNING: Could not install Python dependencies automatically."
        echo "AD Simulator may not work. Install manually with:"
        echo "  pip3 install ldaptor twisted pydantic cryptography click"
    }
fi

# Set proper permissions for the chrome-sandbox
SANDBOX="$APP_DIR/chrome-sandbox"
if [ -f "$SANDBOX" ]; then
    chown root:root "$SANDBOX"
    chmod 4755 "$SANDBOX"
fi

# Configure passwordless sudo for iptables (needed for DSCP marking on SYN packets)
SUDOERS_FILE="/etc/sudoers.d/identity-fuzzer-iptables"
if [ ! -f "$SUDOERS_FILE" ]; then
    echo "Configuring iptables permissions for DSCP marking..."
    # Allow all users to run iptables without password (needed for DSCP on SYN packets)
    echo "ALL ALL=(ALL) NOPASSWD: /usr/sbin/iptables" > "$SUDOERS_FILE"
    chmod 440 "$SUDOERS_FILE"
fi

# Compile native DSCP addon if gcc and node headers are available
ADDON_DIR="$APP_DIR/resources/app.asar.unpacked/lib/traffic"
ADDON_FILE="$ADDON_DIR/set_tos_napi.node"
if [ ! -f "$ADDON_FILE" ] && command -v gcc > /dev/null 2>&1; then
    echo "Compiling native DSCP addon..."
    mkdir -p "$ADDON_DIR"
    cat > /tmp/set_tos_napi.c << 'ADDONEOF'
#include <node_api.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

static napi_value SetTOS(napi_env env, napi_callback_info info) {
    size_t argc = 2; napi_value args[2];
    napi_get_cb_info(env, info, &argc, args, NULL, NULL);
    int32_t fd, tos;
    napi_get_value_int32(env, args[0], &fd);
    napi_get_value_int32(env, args[1], &tos);
    int result = setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
    int readback = -1;
    if (result == 0) { socklen_t len = sizeof(readback); getsockopt(fd, IPPROTO_IP, IP_TOS, &readback, &len); }
    napi_value ret; napi_create_int32(env, readback, &ret); return ret;
}

static napi_value CreateSocketWithTOS(napi_env env, napi_callback_info info) {
    size_t argc = 1; napi_value args[1];
    napi_get_cb_info(env, info, &argc, args, NULL, NULL);
    int32_t tos; napi_get_value_int32(env, args[0], &tos);
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { napi_value ret; napi_create_int32(env, -errno, &ret); return ret; }
    if (tos > 0) setsockopt(fd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos));
    int one = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    int flags = fcntl(fd, F_GETFL, 0); fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    napi_value ret; napi_create_int32(env, fd, &ret); return ret;
}

static napi_value Init(napi_env env, napi_value exports) {
    napi_value fn1, fn2;
    napi_create_function(env, NULL, 0, SetTOS, NULL, &fn1);
    napi_set_named_property(env, exports, "setTOS", fn1);
    napi_create_function(env, NULL, 0, CreateSocketWithTOS, NULL, &fn2);
    napi_set_named_property(env, exports, "createSocketWithTOS", fn2);
    return exports;
}
NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
ADDONEOF
    # Try to find Node.js headers
    NODE_INC=$(find /usr/include -name "node_api.h" -exec dirname {} \; 2>/dev/null | head -1)
    if [ -n "$NODE_INC" ]; then
        gcc -shared -fPIC -o "$ADDON_FILE" /tmp/set_tos_napi.c -I"$NODE_INC" 2>/dev/null && {
            echo "Native DSCP addon compiled successfully."
        } || {
            echo "WARNING: Could not compile native DSCP addon. DSCP marking may not work on SYN packets."
        }
    else
        echo "WARNING: Node.js headers not found. Install nodejs-dev for native DSCP addon."
    fi
    rm -f /tmp/set_tos_napi.c
fi

# Update desktop database
if command -v update-desktop-database > /dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications 2>/dev/null || true
fi

echo "Identity Fuzzer installed successfully."
echo "Launch from your application menu or run: identity-fuzzer"
