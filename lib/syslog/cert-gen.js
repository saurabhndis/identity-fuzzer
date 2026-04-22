// SSL certificate generation for syslog sender simulator
// Port of: AI-Agent/anton/apps/useridd/syslogsender/src/syslog_sender_sim/utils/cert_manager.py
//
// Uses Node.js built-in crypto module — works on macOS, Linux, and Windows.
// PAN-OS requires RSA keys with minimum 2048-bit size.

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/**
 * Generate a self-signed certificate and private key using Node.js crypto.
 *
 * @param {Object} [opts]
 * @param {string} [opts.commonName='syslog-sender-sim']
 * @param {string} [opts.organization='PAN-OS Test']
 * @param {number} [opts.days=365]
 * @param {number} [opts.keySize=2048]
 * @param {string} [opts.outputDir='./certs']
 * @param {string} [opts.certFilename='client.pem']
 * @param {string} [opts.keyFilename='client-key.pem']
 * @returns {{ certPath: string, keyPath: string }}
 */
function generateSelfSigned(opts = {}) {
  const cn = opts.commonName || 'syslog-sender-sim';
  const org = opts.organization || 'PAN-OS Test';
  const days = opts.days || 365;
  const keySize = opts.keySize || 2048;
  const outputDir = opts.outputDir || './certs';
  const certFilename = opts.certFilename || 'client.pem';
  const keyFilename = opts.keyFilename || 'client-key.pem';

  if (keySize < 2048) {
    throw new Error(`Key size must be >= 2048 bits (got ${keySize}). PAN-OS rejects keys smaller than 2048 bits.`);
  }

  fs.mkdirSync(outputDir, { recursive: true });

  const certPath = path.join(outputDir, certFilename);
  const keyPath = path.join(outputDir, keyFilename);

  // Generate RSA key pair
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: keySize,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  // Generate self-signed certificate using X509Certificate (Node.js 15+)
  // For broader compatibility, use openssl as fallback
  try {
    const cert = _generateCertWithNodeCrypto(privateKey, publicKey, cn, org, days, null, null, true);
    fs.writeFileSync(certPath, cert);
  } catch (e) {
    // Fallback to openssl CLI if Node.js X509 API not available
    _generateCertWithOpenSSL(certPath, keyPath, cn, org, days, keySize);
    return {
      certPath: path.resolve(certPath),
      keyPath: path.resolve(keyPath),
    };
  }

  fs.writeFileSync(keyPath, privateKey);
  try { fs.chmodSync(keyPath, 0o600); } catch (_) {} // chmod may fail on Windows

  return {
    certPath: path.resolve(certPath),
    keyPath: path.resolve(keyPath),
  };
}

/**
 * Generate a CA certificate and a CA-signed client certificate.
 *
 * @param {Object} [opts]
 * @param {string} [opts.caCN='syslog-sim-ca']
 * @param {string} [opts.clientCN='syslog-sender-sim']
 * @param {string} [opts.organization='PAN-OS Test']
 * @param {number} [opts.days=365]
 * @param {number} [opts.keySize=2048]
 * @param {string} [opts.outputDir='./certs']
 * @returns {{ caCertPath: string, caKeyPath: string, clientCertPath: string, clientKeyPath: string }}
 */
function generateCAAndClient(opts = {}) {
  const caCN = opts.caCN || 'syslog-sim-ca';
  const clientCN = opts.clientCN || 'syslog-sender-sim';
  const org = opts.organization || 'PAN-OS Test';
  const days = opts.days || 365;
  const keySize = opts.keySize || 2048;
  const outputDir = opts.outputDir || './certs';

  if (keySize < 2048) {
    throw new Error(`Key size must be >= 2048 bits (got ${keySize}).`);
  }

  fs.mkdirSync(outputDir, { recursive: true });

  const caCertPath = path.join(outputDir, 'ca.pem');
  const caKeyPath = path.join(outputDir, 'ca-key.pem');
  const clientCertPath = path.join(outputDir, 'client.pem');
  const clientKeyPath = path.join(outputDir, 'client-key.pem');

  // Generate CA key pair
  const caKeys = crypto.generateKeyPairSync('rsa', {
    modulusLength: keySize,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  // Generate client key pair
  const clientKeys = crypto.generateKeyPairSync('rsa', {
    modulusLength: keySize,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });

  try {
    // Generate CA self-signed cert
    const caCert = _generateCertWithNodeCrypto(
      caKeys.privateKey, caKeys.publicKey, caCN, org, days, null, null, true
    );
    fs.writeFileSync(caCertPath, caCert);

    // Generate client cert signed by CA
    const clientCert = _generateCertWithNodeCrypto(
      caKeys.privateKey, clientKeys.publicKey, clientCN, org, days, caCN, org, false
    );
    fs.writeFileSync(clientCertPath, clientCert);
  } catch (e) {
    // Fallback to openssl CLI
    _generateCAAndClientWithOpenSSL(
      caCertPath, caKeyPath, clientCertPath, clientKeyPath,
      caCN, clientCN, org, days, keySize
    );
    return {
      caCertPath: path.resolve(caCertPath),
      caKeyPath: path.resolve(caKeyPath),
      clientCertPath: path.resolve(clientCertPath),
      clientKeyPath: path.resolve(clientKeyPath),
    };
  }

  fs.writeFileSync(caKeyPath, caKeys.privateKey);
  fs.writeFileSync(clientKeyPath, clientKeys.privateKey);
  try { fs.chmodSync(caKeyPath, 0o600); } catch (_) {}
  try { fs.chmodSync(clientKeyPath, 0o600); } catch (_) {}

  return {
    caCertPath: path.resolve(caCertPath),
    caKeyPath: path.resolve(caKeyPath),
    clientCertPath: path.resolve(clientCertPath),
    clientKeyPath: path.resolve(clientKeyPath),
  };
}

/**
 * Generate a certificate using Node.js crypto.X509Certificate (Node 15+).
 * Uses crypto.createCertificate if available (Node 21+), otherwise falls back.
 * @private
 */
function _generateCertWithNodeCrypto(signingKey, publicKey, cn, org, days, issuerCN, issuerOrg, isSelfSigned) {
  // Node.js doesn't have a built-in X509 certificate builder in older versions.
  // Electron 40.x ships with Node 20.x which has crypto.X509Certificate for reading
  // but not for creating certificates. We use openssl as the primary method.
  throw new Error('Node.js X509 certificate creation not available — using openssl fallback');
}

/**
 * Generate self-signed cert using openssl CLI (cross-platform fallback).
 * @private
 */
function _generateCertWithOpenSSL(certPath, keyPath, cn, org, days, keySize) {
  const { execSync } = require('child_process');
  const subject = _buildSubject(cn, org);

  execSync(
    `openssl req -x509 -newkey rsa:${keySize} -keyout "${keyPath}" -out "${certPath}" ` +
    `-days ${days} -nodes -subj "${subject}" 2>${_devNull()}`,
    { stdio: 'pipe' }
  );

  try { fs.chmodSync(keyPath, 0o600); } catch (_) {}
}

/**
 * Generate CA + client certs using openssl CLI.
 * @private
 */
function _generateCAAndClientWithOpenSSL(caCertPath, caKeyPath, clientCertPath, clientKeyPath, caCN, clientCN, org, days, keySize) {
  const { execSync } = require('child_process');
  const caSubject = _buildSubject(caCN, org);
  const clientSubject = _buildSubject(clientCN, org);
  const outputDir = path.dirname(caCertPath);
  const csrPath = path.join(outputDir, 'client.csr');

  // Generate CA
  execSync(
    `openssl req -x509 -newkey rsa:${keySize} -keyout "${caKeyPath}" -out "${caCertPath}" ` +
    `-days ${days} -nodes -subj "${caSubject}" 2>${_devNull()}`,
    { stdio: 'pipe' }
  );

  // Generate client CSR
  execSync(
    `openssl req -newkey rsa:${keySize} -keyout "${clientKeyPath}" -out "${csrPath}" ` +
    `-nodes -subj "${clientSubject}" 2>${_devNull()}`,
    { stdio: 'pipe' }
  );

  // Sign client cert with CA
  execSync(
    `openssl x509 -req -in "${csrPath}" -CA "${caCertPath}" -CAkey "${caKeyPath}" ` +
    `-CAcreateserial -out "${clientCertPath}" -days ${days} 2>${_devNull()}`,
    { stdio: 'pipe' }
  );

  // Cleanup
  try { fs.unlinkSync(csrPath); } catch (_) {}
  try { fs.unlinkSync(path.join(outputDir, 'ca.srl')); } catch (_) {}
  try { fs.chmodSync(caKeyPath, 0o600); } catch (_) {}
  try { fs.chmodSync(clientKeyPath, 0o600); } catch (_) {}
}

/**
 * Build an OpenSSL subject string, escaping for the current platform.
 * @private
 */
function _buildSubject(cn, org) {
  // On Windows, openssl subject format uses / separators same as Unix
  return `/CN=${cn}/O=${org}`;
}

/**
 * Get the null device path for the current platform.
 * @private
 */
function _devNull() {
  return process.platform === 'win32' ? 'NUL' : '/dev/null';
}

/**
 * Load basic information about a PEM certificate.
 * Uses Node.js crypto.X509Certificate (available in Node 15+).
 * @param {string} certPath
 * @returns {Object}
 */
function loadCertInfo(certPath) {
  try {
    const certData = fs.readFileSync(certPath, 'utf8');
    const cert = new crypto.X509Certificate(certData);
    return {
      subject: cert.subject,
      issuer: cert.issuer,
      serialNumber: cert.serialNumber,
      notValidBefore: cert.validFrom,
      notValidAfter: cert.validTo,
      fingerprint: cert.fingerprint256,
    };
  } catch (e) {
    // Fallback to openssl CLI
    try {
      const { execSync } = require('child_process');
      const output = execSync(
        `openssl x509 -in "${certPath}" -noout -subject -issuer -dates -serial 2>${_devNull()}`,
        { encoding: 'utf8' }
      );
      const info = {};
      const subjectMatch = output.match(/subject\s*=\s*(.+)/i);
      if (subjectMatch) info.subject = subjectMatch[1].trim();
      const issuerMatch = output.match(/issuer\s*=\s*(.+)/i);
      if (issuerMatch) info.issuer = issuerMatch[1].trim();
      const notBeforeMatch = output.match(/notBefore\s*=\s*(.+)/i);
      if (notBeforeMatch) info.notValidBefore = notBeforeMatch[1].trim();
      const notAfterMatch = output.match(/notAfter\s*=\s*(.+)/i);
      if (notAfterMatch) info.notValidAfter = notAfterMatch[1].trim();
      return info;
    } catch (e2) {
      return { error: e2.message };
    }
  }
}

module.exports = {
  generateSelfSigned,
  generateCAAndClient,
  loadCertInfo,
};
