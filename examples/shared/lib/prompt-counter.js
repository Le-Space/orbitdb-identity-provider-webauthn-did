/**
 * How many times the page asked the authenticator.
 *
 * The READMEs promise prompt counts per step; this is the number the demos
 * show next to the identity so that promise can be checked, by a person or
 * by a test. Counting happens at the WebAuthn API: every `create()` and
 * `get()` is one interaction with the authenticator, whatever it was for.
 */
import { writable } from 'svelte/store';

export const promptCounts = writable({ create: 0, get: 0 });

let installed = false;

/** Wrap `navigator.credentials` once; safe to call more than once. */
export function installPromptCounter() {
  if (installed || typeof navigator === 'undefined' || !navigator.credentials)
    return;
  installed = true;
  const credentials = navigator.credentials;
  for (const method of ['create', 'get']) {
    const original = credentials[method].bind(credentials);
    credentials[method] = async (...args) => {
      promptCounts.update((c) => ({ ...c, [method]: c[method] + 1 }));
      return original(...args);
    };
  }
}
