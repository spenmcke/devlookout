'use strict';

function median(values) {
  if (!values.length) return null;
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

class SetBaseline {
  constructor({ defaults = [], minimumObservations = 3, noveltySeconds = 259200, maximumValues = 10000 } = {}) {
    if (!Number.isSafeInteger(minimumObservations) || minimumObservations < 1 || !Number.isFinite(noveltySeconds) || noveltySeconds < 0 || !Number.isSafeInteger(maximumValues) || maximumValues < 1) throw new Error('Invalid set baseline parameters');
    this.minimumObservations = minimumObservations;
    this.noveltySeconds = noveltySeconds;
    this.maximumValues = maximumValues;
    this.values = new Map(defaults.slice(0, maximumValues).map((value) => [String(value), { count: minimumObservations, firstSeen: null, lastSeen: null, trusted: true }]));
  }

  observe(value, observedAt, { allowLearning = true, activeAlert = false } = {}) {
    const existing = this.values.get(value);
    const novel = !existing || !existing.trusted;
    const baselineReady = [...this.values.values()].some((record) => record.trusted);
    if (allowLearning && !activeAlert && (existing || this.values.size < this.maximumValues)) {
      const record = existing || { count: 0, firstSeen: observedAt, lastSeen: observedAt, trusted: false };
      record.count += 1;
      record.firstSeen ||= observedAt;
      record.lastSeen = observedAt;
      if (record.count >= this.minimumObservations && Date.parse(observedAt) - Date.parse(record.firstSeen) >= this.noveltySeconds * 1000) record.trusted = true;
      this.values.set(value, record);
    }
    const anomaly = baselineReady && novel;
    return { anomaly, state: baselineReady ? (anomaly ? 'novel' : 'normal') : 'learning', reason: anomaly ? 'value is not in the trusted relationship set' : null, value };
  }

  snapshot() { return { kind: 'set', minimumObservations: this.minimumObservations, noveltySeconds: this.noveltySeconds, maximumValues: this.maximumValues, values: Object.fromEntries([...this.values.entries()].sort(([a], [b]) => a.localeCompare(b))) }; }

  static fromSnapshot(snapshot) {
    const baseline = new SetBaseline({ minimumObservations: snapshot.minimumObservations, noveltySeconds: snapshot.noveltySeconds, maximumValues: snapshot.maximumValues || 10000 });
    const entries = Object.entries(snapshot.values || {});
    if (entries.length > baseline.maximumValues) throw new Error('Set baseline snapshot exceeds value capacity');
    baseline.values = new Map(entries);
    return baseline;
  }
}

class RobustNumericBaseline {
  constructor({ defaults = [], minimumSamples = 12, warningDeviations = 6, criticalDeviations = 10, maximumSamples = 672 } = {}) {
    if (!Number.isSafeInteger(minimumSamples) || minimumSamples < 3 || !Number.isFinite(warningDeviations) || warningDeviations <= 0 || !Number.isFinite(criticalDeviations) || criticalDeviations <= warningDeviations || !Number.isSafeInteger(maximumSamples) || maximumSamples < minimumSamples) throw new Error('Invalid numeric baseline parameters');
    this.samples = defaults.filter(Number.isFinite).slice(-maximumSamples);
    this.minimumSamples = minimumSamples;
    this.warningDeviations = warningDeviations;
    this.criticalDeviations = criticalDeviations;
    this.maximumSamples = maximumSamples;
  }

  score(value, { allowLearning = true, activeAlert = false } = {}) {
    if (!Number.isFinite(value)) throw new TypeError('Numeric baseline value must be finite');
    const center = median(this.samples);
    const deviation = center === null ? null : median(this.samples.map((sample) => Math.abs(sample - center)));
    const scale = deviation === 0 ? Math.max(Math.abs(center) * 0.05, 1) : deviation * 1.4826;
    const z = center === null ? 0 : Math.abs(value - center) / scale;
    const guardReady = this.samples.length >= 3;
    const state = !guardReady ? 'learning' : z >= this.criticalDeviations ? 'critical' : z >= this.warningDeviations ? 'warning' : this.samples.length < this.minimumSamples ? 'learning' : 'normal';
    if (allowLearning && !activeAlert && state !== 'warning' && state !== 'critical') {
      this.samples.push(value);
      if (this.samples.length > this.maximumSamples) this.samples.shift();
    }
    return { anomaly: state === 'warning' || state === 'critical', state, value, center, mad: deviation, robustDeviation: z, sampleCount: this.samples.length };
  }

  snapshot() { return { kind: 'robust_numeric', minimumSamples: this.minimumSamples, warningDeviations: this.warningDeviations, criticalDeviations: this.criticalDeviations, maximumSamples: this.maximumSamples, samples: [...this.samples] }; }

  static fromSnapshot(snapshot) {
    return new RobustNumericBaseline({ defaults: snapshot.samples || [], minimumSamples: snapshot.minimumSamples, warningDeviations: snapshot.warningDeviations, criticalDeviations: snapshot.criticalDeviations, maximumSamples: snapshot.maximumSamples });
  }
}

module.exports = { median, SetBaseline, RobustNumericBaseline };
