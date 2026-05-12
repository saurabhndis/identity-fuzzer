/**
 * afterPack hook for electron-builder.
 * Installs Python dependencies for the AD Simulator into a vendored
 * directory inside the packaged app so the .deb works without requiring
 * the user to pip-install anything.
 *
 * Set SKIP_PYTHON_VENDOR=1 to skip vendoring (useful on low-disk machines;
 * the postinst script will install deps on the target instead).
 */
'use strict';

const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

module.exports = async function afterPack(context) {
  // Allow skipping Python vendoring via environment variable
  if (process.env.SKIP_PYTHON_VENDOR === '1') {
    console.log('[afterPack] SKIP_PYTHON_VENDOR=1 — skipping Python dependency vendoring.');
    console.log('[afterPack] Python deps will be installed by postinst on the target machine.');
    return;
  }

  // With asarUnpack, Python files end up in app.asar.unpacked/
  const unpackedDir = path.join(context.appOutDir, 'resources', 'app.asar.unpacked');
  const adSimDir = path.join(unpackedDir, 'lib', 'ad-simulator');
  const requirementsFile = path.join(adSimDir, 'requirements.txt');
  const vendorDir = path.join(adSimDir, 'vendor');

  // Only run if the ad-simulator directory exists in the packaged app
  if (!fs.existsSync(requirementsFile)) {
    console.log('[afterPack] No ad-simulator/requirements.txt found at:', requirementsFile);
    console.log('[afterPack] Skipping Python vendor install.');
    return;
  }

  console.log('[afterPack] Found requirements.txt at:', requirementsFile);
  console.log('[afterPack] Installing Python dependencies into vendor directory...');

  try {
    // Create vendor directory
    fs.mkdirSync(vendorDir, { recursive: true });

    // Install Python dependencies into the vendor directory
    const platform = process.platform;
    let pipCmd = `python3 -m pip install --target "${vendorDir}" -r "${requirementsFile}" --no-cache-dir`;

    if (platform === 'darwin') {
      // Cross-compiling from macOS to Linux: install pure-python packages only
      console.log('[afterPack] Cross-compiling from macOS — installing pure-Python packages.');
      pipCmd += ' --only-binary=:none: --no-compile';
    }

    execSync(pipCmd, { stdio: 'inherit', timeout: 120000 });

    console.log('[afterPack] Python dependencies installed successfully.');
  } catch (err) {
    console.warn('[afterPack] WARNING: Failed to install Python dependencies.');
    console.warn('[afterPack] The AD Simulator module may not work without them.');
    console.warn('[afterPack] Error:', err.message);
    console.warn('[afterPack] Users can manually install with:');
    console.warn('[afterPack]   pip3 install ldaptor twisted pydantic cryptography click');
  }
};
