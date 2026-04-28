// PAN-OS XML API User-ID constants
// Reference: PAN-OS Admin Guide — User-ID XML API

'use strict';

/**
 * Default HTTPS port for PAN-OS management interface.
 */
const DEFAULT_API_PORT = 443;

/**
 * PAN-OS API endpoint path.
 */
const API_ENDPOINT = '/api/';

/**
 * uid-message version sent in the XML envelope.
 */
const UID_MESSAGE_VERSION = '2.0';

/**
 * uid-message type — always "update" for User-ID operations.
 */
const UID_MESSAGE_TYPE = 'update';

/**
 * Maximum number of entries per uid-message payload.
 * PAN-OS silently drops entries beyond this limit.
 */
const MAX_ENTRIES_PER_MESSAGE = 500;

/**
 * Default timeout (seconds) for IP-user mappings.
 * 0 = never expire; omitted = use firewall global default.
 */
const DEFAULT_MAPPING_TIMEOUT = 0;

/**
 * Payload operation types.
 */
const PAYLOAD_TYPE = {
  LOGIN: 'login',
  LOGOUT: 'logout',
  GROUPS: 'groups',
  TAG_REGISTER: 'tag-register',
  TAG_UNREGISTER: 'tag-unregister',
};

/**
 * Scenario execution status.
 */
const SCENARIO_STATUS = {
  IDLE: 'idle',
  RUNNING: 'running',
  DONE: 'done',
  ERROR: 'error',
};

/**
 * Transport state.
 */
const TRANSPORT_STATE = {
  DISCONNECTED: 'disconnected',
  CONNECTED: 'connected',
  ERROR: 'error',
};

module.exports = {
  DEFAULT_API_PORT,
  API_ENDPOINT,
  UID_MESSAGE_VERSION,
  UID_MESSAGE_TYPE,
  MAX_ENTRIES_PER_MESSAGE,
  DEFAULT_MAPPING_TIMEOUT,
  PAYLOAD_TYPE,
  SCENARIO_STATUS,
  TRANSPORT_STATE,
};
