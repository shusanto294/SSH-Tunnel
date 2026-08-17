import { describe, expect, it } from 'vitest';
import {
  blockDurationFor,
  socketSuspicionWeight,
  suspicionWeight,
} from '../src/security/suspicion';

describe('suspicion scoring', () => {
  it('never punishes ordinary reads', () => {
    // The landing page calls this while signed out on every visit. Scoring it
    // would ban anyone who reads the site.
    expect(suspicionWeight({ method: 'GET', path: 'auth/me', status: 401 })).toBe(0);
    expect(suspicionWeight({ method: 'GET', path: 'config', status: 200 })).toBe(0);
    expect(suspicionWeight({ method: 'GET', path: 'servers', status: 200 })).toBe(0);
  });

  it('scores wrong passwords', () => {
    expect(suspicionWeight({ method: 'POST', path: 'auth/login', status: 401 })).toBe(2);
    expect(suspicionWeight({ method: 'POST', path: 'auth/login', status: 200 })).toBe(0);
  });

  it('scores rejected invites and account probing harder than a typo', () => {
    const login = suspicionWeight({ method: 'POST', path: 'auth/login', status: 401 });
    const register = suspicionWeight({ method: 'POST', path: 'auth/register', status: 403 });
    expect(register).toBeGreaterThan(login);
  });

  it('scores rate-limit trips heavily', () => {
    expect(suspicionWeight({ method: 'POST', path: 'auth/login', status: 429 })).toBe(5);
  });

  it('scores reaching for another account, and probing for endpoints', () => {
    expect(suspicionWeight({ method: 'DELETE', path: 'servers/abc', status: 404 })).toBe(2);
    expect(suspicionWeight({ method: 'GET', path: 'wp-admin', status: 404 })).toBe(1);
  });

  it('scores rejected socket upgrades', () => {
    expect(socketSuspicionWeight(101)).toBe(0);
    expect(socketSuspicionWeight(401)).toBe(1);
    expect(socketSuspicionWeight(403)).toBe(3);
    expect(socketSuspicionWeight(429)).toBe(5);
  });
});

describe('block escalation', () => {
  it('tolerates a handful of mistakes', () => {
    // Five wrong passwords is a person who forgot, not an attack.
    expect(blockDurationFor(0)).toBe(0);
    expect(blockDurationFor(9)).toBe(0);
  });

  it('escalates the longer it continues', () => {
    expect(blockDurationFor(10)).toBe(5 * 60);
    expect(blockDurationFor(25)).toBe(60 * 60);
    expect(blockDurationFor(50)).toBe(24 * 60 * 60);
    expect(blockDurationFor(500)).toBe(24 * 60 * 60);
  });

  it('never goes backwards as strikes accumulate', () => {
    let previous = 0;
    for (let strikes = 0; strikes <= 100; strikes++) {
      const duration = blockDurationFor(strikes);
      expect(duration).toBeGreaterThanOrEqual(previous);
      previous = duration;
    }
  });

  it('blocks a password-guessing run in well under 20 attempts', () => {
    // Each wrong password is worth 2, so the first block lands at 5 attempts.
    const perFailure = suspicionWeight({ method: 'POST', path: 'auth/login', status: 401 });
    let strikes = 0;
    let attempts = 0;
    while (blockDurationFor(strikes) === 0) {
      strikes += perFailure;
      attempts++;
    }
    expect(attempts).toBeLessThanOrEqual(5);
  });
});
