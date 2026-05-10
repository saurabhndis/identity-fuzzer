// Traffic Module — re-exports for clean imports
// Usage: const traffic = require('./lib/traffic');

'use strict';

const constants = require('./constants');
const { TransportStats, TCPTransport, TLSTransport, createTransport } = require('./transport');
const {
  buildHTTPRequest,
  buildHTTPResponse,
  buildChunkedBody,
  parseHTTPMessage,
  hasHeader,
  jsonBody,
  healthResponse,
  echoResponse,
} = require('./http-builder');
const {
  buildH2Preface,
  buildH2Frame,
  buildH2Settings,
  buildH2DefaultSettings,
  hpackEncodeLiteral,
  hpackEncodeInteger,
  buildH2Headers,
  buildH2GetRequest,
  buildH2PostRequest,
  buildH2Data,
  buildH2Ping,
  buildH2Goaway,
  buildH2RstStream,
  buildH2WindowUpdate,
  buildH2Priority,
  buildH2PushPromise,
  parseH2FrameHeader,
  parseH2Frames,
} = require('./http2-builder');
const {
  TRAFFIC_CATEGORIES,
  TRAFFIC_CATEGORY_SEVERITY,
  TRAFFIC_CATEGORY_DEFAULT_DISABLED,
  TRAFFIC_SCENARIOS,
  getTrafficScenario,
  getTrafficScenariosByCategory,
  listTrafficScenarios,
  listTrafficClientScenarios,
  listTrafficServerScenarios,
} = require('./scenarios');
const { TrafficFuzzerClient } = require('./client');
const { TrafficFuzzerServer } = require('./server');


module.exports = {
  // Constants
  ...constants,

  // Transport
  TransportStats,
  TCPTransport,
  TLSTransport,
  createTransport,

  // HTTP/1.1 Builder
  buildHTTPRequest,
  buildHTTPResponse,
  buildChunkedBody,
  parseHTTPMessage,
  hasHeader,
  jsonBody,
  healthResponse,
  echoResponse,

  // HTTP/2 Builder
  buildH2Preface,
  buildH2Frame,
  buildH2Settings,
  buildH2DefaultSettings,
  hpackEncodeLiteral,
  hpackEncodeInteger,
  buildH2Headers,
  buildH2GetRequest,
  buildH2PostRequest,
  buildH2Data,
  buildH2Ping,
  buildH2Goaway,
  buildH2RstStream,
  buildH2WindowUpdate,
  buildH2Priority,
  buildH2PushPromise,
  parseH2FrameHeader,
  parseH2Frames,

  // Scenarios
  TRAFFIC_CATEGORIES,
  TRAFFIC_CATEGORY_SEVERITY,
  TRAFFIC_CATEGORY_DEFAULT_DISABLED,
  TRAFFIC_SCENARIOS,
  getTrafficScenario,
  getTrafficScenariosByCategory,
  listTrafficScenarios,
  listTrafficClientScenarios,
  listTrafficServerScenarios,

  // Engines
  TrafficFuzzerClient,
  TrafficFuzzerServer,
};
