// XML API User-ID module — re-exports for clean imports
// Usage: const xmlapi = require('./lib/xmlapi');

'use strict';

const constants = require('./constants');
const {
  xmlEscape,
  formatUsername,
  buildLoginPayload,
  buildLogoutPayload,
  buildGroupPayload,
  buildTagRegisterPayload,
  buildTagUnregisterPayload,
  buildUidMessage,
  buildMultiPayload,
  parseResponse,
} = require('./xml-builder');
const { XmlApiTransport, TransportStats } = require('./transport');
const { XmlApiGenerator } = require('./generator');
const {
  makeResult,
  runLoginLogout,
  runBulkLogin,
  runGroupPush,
  runTagOperation,
  runMixed,
  runEdgeCases,
  EDGE_CASE_TESTS,
} = require('./scenarios');

module.exports = {
  // Constants
  ...constants,

  // XML Builder
  xmlEscape,
  formatUsername,
  buildLoginPayload,
  buildLogoutPayload,
  buildGroupPayload,
  buildTagRegisterPayload,
  buildTagUnregisterPayload,
  buildUidMessage,
  buildMultiPayload,
  parseResponse,

  // Transport
  XmlApiTransport,
  TransportStats,

  // Generator
  XmlApiGenerator,

  // Scenarios
  makeResult,
  runLoginLogout,
  runBulkLogin,
  runGroupPush,
  runTagOperation,
  runMixed,
  runEdgeCases,
  EDGE_CASE_TESTS,
};
