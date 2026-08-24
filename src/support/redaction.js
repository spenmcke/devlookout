'use strict';

const RULES = [
  { category: 'private_key', high: true, pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { category: 'lookout_token', high: true, pattern: /\b(?:lst|lrc|lsp)_[A-Za-z0-9_-]{43}\b/g },
  { category: 'authorization', high: true, pattern: /\bAuthorization\s*:\s*(?:Bearer|Basic)\s+[A-Za-z0-9+/_=.-]{8,}/gi },
  { category: 'cloud_access_key', high: true, pattern: /\b(?:AKIA|ASIA|A3T[A-Z0-9]|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b/g },
  { category: 'jwt', high: true, pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b/g },
  { category: 'supabase_key', high: true, pattern: /\bsbp_[A-Za-z0-9_-]{20,}\b/g },
  { category: 'webhook_secret', high: true, pattern: /\bwhsec_[A-Za-z0-9+/_=-]{16,}(?![A-Za-z0-9+/_=-])/g },
  { category: 'secret_url', high: true, pattern: /https?:\/\/[^\s/@:]+:[^\s/@]+@[^\s]+/gi },
  { category: 'secret_url', high: true, pattern: /https?:\/\/[^\s?#]+\?(?:[^\s#]*&)?(?:access_token|api_key|apikey|key|secret|signature|sig|token|webhook)=[^\s&#]+/gi },
  { category: 'environment_secret', high: true, pattern: /\b[A-Z][A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL)[A-Z0-9_]*\s*=\s*(?:(?:"[^"\r\n]+")|(?:'[^'\r\n]+')|(?:[^\s\r\n]+))/gi },
  { category: 'basic_credential', high: true, pattern: /\b(?:password|passwd|client_secret|api[_-]?key|access[_-]?token)\s*[:=]\s*[^\s,;]{8,}/gi }
];

function redactSupportInput(input) {
  const placeholders = new Map();
  const counts = {};
  let blocked = false;
  let sequence = 0;
  const replace = (text) => {
    let output = text;
    for (const rule of RULES) {
      rule.pattern.lastIndex = 0;
      output = output.replace(rule.pattern, (match) => {
        let placeholder = placeholders.get(match);
        if (!placeholder) {
          sequence += 1;
          placeholder = `[REDACTED_${rule.category.toUpperCase()}_${sequence}]`;
          placeholders.set(match, placeholder);
          counts[rule.category] = (counts[rule.category] || 0) + 1;
        }
        if (rule.high) blocked = true;
        return placeholder;
      });
    }
    return output;
  };
  const visit = (value) => {
    if (typeof value === 'string') return replace(value);
    if (Array.isArray(value)) return value.map(visit);
    if (value && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, visit(item)]));
    return value;
  };
  return { value: visit(input), blocked, categories: Object.keys(counts).sort(), counts, redactionCount: Object.values(counts).reduce((sum, count) => sum + count, 0) };
}

module.exports = { redactSupportInput, SUPPORT_SECRET_RULES: RULES };
