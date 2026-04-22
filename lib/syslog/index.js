// Syslog Sender Simulator — re-exports for clean imports
// Usage: const syslog = require('./lib/syslog');

const constants = require('./constants');
const { IPGenerator } = require('./ip-generator');
const { TEMPLATES, getTemplate, listTemplates, renderTemplate, syslogTimestamp } = require('./templates');
const { PREDEFINED_PROFILES, formatProfileMessage } = require('./profiles');
const { MessageGenerator } = require('./generator');
const { SSLTransport, UDPTransport, TransportStats, createTransport } = require('./transport');
const { runLoginLogout, runStress, runEdgeCases, EDGE_CASE_TESTS, makeResult } = require('./scenarios');
const { generateSelfSigned, generateCAAndClient, loadCertInfo } = require('./cert-gen');

module.exports = {
  // Constants
  ...constants,

  // IP Generator
  IPGenerator,

  // Templates
  TEMPLATES,
  getTemplate,
  listTemplates,
  renderTemplate,
  syslogTimestamp,

  // Profiles
  PREDEFINED_PROFILES,
  formatProfileMessage,

  // Message Generator
  MessageGenerator,

  // Transport
  SSLTransport,
  UDPTransport,
  TransportStats,
  createTransport,

  // Scenarios
  runLoginLogout,
  runStress,
  runEdgeCases,
  EDGE_CASE_TESTS,
  makeResult,

  // Certificate Generation
  generateSelfSigned,
  generateCAAndClient,
  loadCertInfo,
};
