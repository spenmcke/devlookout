'use strict';

const { selectorSpecificity } = require('./predicates');

const SEVERITIES = new Set(['informational', 'low', 'medium', 'high', 'critical']);

function applyOverlay(rule, overlay, now = new Date()) {
  if (!overlay || overlay.ruleId !== rule.id) throw new Error('Overlay must target the rule being tuned');
  if (typeof overlay.owner !== 'string' || !overlay.owner.trim()) throw new Error('Overlay requires an owner');
  if (typeof overlay.reason !== 'string' || overlay.reason.trim().length < 10) throw new Error('Overlay requires a meaningful reason');
  if (Number.isNaN(Date.parse(overlay.expiresAt))) throw new Error('Overlay requires an expiration timestamp');
  if (Date.parse(overlay.expiresAt) <= now.getTime()) throw new Error('Overlay is expired');
  if (overlay.severity && !SEVERITIES.has(overlay.severity)) throw new Error('Overlay severity is invalid');
  if (overlay.threshold !== undefined && (!Number.isInteger(overlay.threshold) || overlay.threshold < 1)) throw new Error('Overlay threshold must be a positive integer');
  if (overlay.windowSeconds !== undefined && (!Number.isInteger(overlay.windowSeconds) || overlay.windowSeconds < 1)) throw new Error('Overlay windowSeconds must be a positive integer');
  for (const exclusion of overlay.exclusions || []) {
    if (!exclusion.selector || selectorSpecificity(exclusion.selector) < 2) throw new Error('Overlay exclusions must be narrowly scoped with at least two constraints or a stable identifier');
    if (typeof exclusion.reason !== 'string' || exclusion.reason.trim().length < 10) throw new Error('Every exclusion requires a meaningful reason');
  }
  return {
    ...structuredClone(rule),
    severity: overlay.severity || rule.severity,
    threshold: overlay.threshold ?? rule.threshold,
    windowSeconds: overlay.windowSeconds ?? rule.windowSeconds,
    scope: overlay.scope ? { ...(rule.scope || {}), ...structuredClone(overlay.scope) } : structuredClone(rule.scope || {}),
    exclusions: [...(rule.exclusions || []), ...(overlay.exclusions || [])].map((value) => structuredClone(value)),
    tuning: { overlayId: overlay.id, owner: overlay.owner, reason: overlay.reason, expiresAt: overlay.expiresAt }
  };
}

module.exports = { applyOverlay };
