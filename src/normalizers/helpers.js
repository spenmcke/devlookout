'use strict';

const crypto = require('node:crypto');

function timestamp(value, fallback = new Date().toISOString()) {
  if (typeof value === 'number' && Number.isFinite(value)) return new Date(value < 100000000000 ? value * 1000 : value).toISOString();
  if (typeof value === 'string' && !Number.isNaN(Date.parse(value))) return new Date(value).toISOString();
  return fallback;
}

function addressEntity(address) {
  return address ? `network-address:${String(address).toLowerCase()}` : null;
}

function endpoint(address, port = null) {
  return address ? { id: addressEntity(address), address: String(address), port: Number.isFinite(Number(port)) ? Number(port) : null } : null;
}

function digestText(value) {
  if (value == null) return null;
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  return crypto.createHash('sha256').update(text).digest('hex');
}

function compact(object) {
  return Object.fromEntries(Object.entries(object).filter(([, value]) => value !== undefined && value !== null));
}

module.exports = { timestamp, addressEntity, endpoint, digestText, compact };
