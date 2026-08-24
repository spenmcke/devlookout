'use strict';

class SupportRateLimitError extends Error {
  constructor(retryAfter) { super('Support capacity is temporarily unavailable'); this.status = 429; this.retryAfter = retryAfter; }
}

class SupportRateLimiter {
  constructor({ clock = () => Date.now(), hourlyLimit = 30, dailyLimit = 200, checkHourlyLimit = 120, globalConcurrency = 8, tokenConcurrency = 2 } = {}) {
    this.clock = clock;
    this.hourlyLimit = hourlyLimit;
    this.dailyLimit = dailyLimit;
    this.checkHourlyLimit = checkHourlyLimit;
    this.globalConcurrency = globalConcurrency;
    this.tokenConcurrency = tokenConcurrency;
    this.askEvents = new Map();
    this.checkEvents = new Map();
    this.activeByToken = new Map();
    this.activeGlobal = 0;
  }

  _events(map, tokenId, windowMs) {
    const now = this.clock();
    const current = (map.get(tokenId) || []).filter((time) => time > now - windowMs);
    map.set(tokenId, current);
    return current;
  }

  acquireGeneration(tokenId) {
    const now = this.clock();
    const daily = this._events(this.askEvents, tokenId, 24 * 60 * 60 * 1000);
    const hourly = daily.filter((time) => time > now - 60 * 60 * 1000);
    if (hourly.length >= this.hourlyLimit || daily.length >= this.dailyLimit) throw new SupportRateLimitError(60);
    if (this.activeGlobal >= this.globalConcurrency || (this.activeByToken.get(tokenId) || 0) >= this.tokenConcurrency) throw new SupportRateLimitError(5);
    daily.push(now);
    this.askEvents.set(tokenId, daily);
    this.activeGlobal += 1;
    this.activeByToken.set(tokenId, (this.activeByToken.get(tokenId) || 0) + 1);
    let released = false;
    return () => {
      if (released) return;
      released = true;
      this.activeGlobal -= 1;
      const active = (this.activeByToken.get(tokenId) || 1) - 1;
      if (active) this.activeByToken.set(tokenId, active); else this.activeByToken.delete(tokenId);
    };
  }

  recordCheck(tokenId) {
    const events = this._events(this.checkEvents, tokenId, 60 * 60 * 1000);
    if (events.length >= this.checkHourlyLimit) throw new SupportRateLimitError(60);
    events.push(this.clock());
  }
}

module.exports = { SupportRateLimiter, SupportRateLimitError };
