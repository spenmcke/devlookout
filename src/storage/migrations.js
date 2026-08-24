'use strict';

class MigrationRegistry {
  constructor(name) { this.name = name; this.steps = new Map(); }

  register(fromVersion, toVersion, migrate) {
    if (!Number.isInteger(fromVersion) || toVersion !== fromVersion + 1 || typeof migrate !== 'function') throw new Error('Migrations must advance exactly one integer schema version');
    if (this.steps.has(fromVersion)) throw new Error(`Migration already registered from version ${fromVersion}`);
    this.steps.set(fromVersion, { toVersion, migrate });
    return this;
  }

  migrate(document, targetVersion) {
    if (!document || !Number.isInteger(document.schemaVersion)) throw new Error(`${this.name} document has no integer schemaVersion`);
    if (document.schemaVersion > targetVersion) throw new Error(`${this.name} document is newer than this runtime`);
    let current = structuredClone(document);
    while (current.schemaVersion < targetVersion) {
      const step = this.steps.get(current.schemaVersion);
      if (!step) throw new Error(`No ${this.name} migration from schema version ${current.schemaVersion}`);
      current = step.migrate(structuredClone(current));
      if (!current || current.schemaVersion !== step.toVersion) throw new Error(`${this.name} migration did not produce schema version ${step.toVersion}`);
    }
    return current;
  }
}

module.exports = { MigrationRegistry };
