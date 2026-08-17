/**
 * Rejects passwords already known from public breaches.
 *
 * Credential stuffing — trying passwords leaked from other sites — is the most
 * common way accounts like these are taken over, and no iteration count helps
 * when the attacker already has the password.
 *
 * Uses the k-anonymity range API: only the first five characters of the SHA-1
 * hash are sent, and the service returns every suffix sharing that prefix. The
 * password itself never leaves the Worker, and the service cannot tell which of
 * the ~500 returned hashes was being asked about.
 */

/** How many appearances make a password unusable here. */
const APPEARANCE_THRESHOLD = 1;

export async function isBreachedPassword(password: string): Promise<boolean> {
  let hash: string;
  try {
    const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(password));
    hash = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0'))
      .join('')
      .toUpperCase();
  } catch {
    return false;
  }

  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  let body: string;
  try {
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'add-padding': 'true' },
      // A slow third party must not hold up registration.
      signal: AbortSignal.timeout(3000),
    });
    if (!response.ok) return false;
    body = await response.text();
  } catch {
    // Fail open, deliberately. An outage at the breach service must not make
    // it impossible to sign up or change a password.
    return false;
  }

  for (const line of body.split('\n')) {
    const separator = line.indexOf(':');
    if (separator < 0) continue;
    if (line.slice(0, separator).trim().toUpperCase() !== suffix) continue;
    const count = Number(line.slice(separator + 1).trim());
    return Number.isFinite(count) && count >= APPEARANCE_THRESHOLD;
  }
  return false;
}

export const BREACHED_MESSAGE =
  'That password appears in a public breach database, so it is already being ' +
  'guessed by attackers. Please choose a different one.';
