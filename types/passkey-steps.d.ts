/** Why the authenticator is being asked; the dialog's wording is keyed on it. */
export type PasskeyPurpose =
  | 'create'
  | 'signing-key'
  | 'identity'
  | 'restore'
  | 'restore-confirm'
  | 'keystore'
  | 'prf'
  | 'metadata'
  | 'wallet'
  | 'sign-entry';

export const PASSKEY_PURPOSES: ReadonlyArray<PasskeyPurpose>;

/** Which prompt comes next, and why. `of` is null when the plan did not say. */
export interface PasskeyStep {
  purpose: PasskeyPurpose;
  n: number;
  of: number | null;
  kind: 'create' | 'get';
}

/** Thrown when somebody stops between two prompts. Nothing has been asked yet. */
export class PasskeyStepCancelled extends Error {
  constructor(message?: string);
}

/**
 * Register what runs before each announced prompt, or `null` to stop.
 * Resolve to let the prompt go ahead, throw to stop it.
 * Returns a function that unregisters this handler, if it is still the one.
 */
export function setPasskeyStepHandler(
  handler: ((step: PasskeyStep) => unknown) | null
): () => void;

/**
 * Run an action whose passkey prompts are numbered. `of` is how many prompts
 * it takes; the first one is not announced unless `askFirst` is set.
 */
export function withPasskeySteps<T>(
  options: number | null | { of?: number | null; askFirst?: boolean },
  run: () => Promise<T> | T
): Promise<T>;

/** Called right before the authenticator is asked; awaits the handler inside a plan. */
export function beforePasskeyCeremony(
  purpose: PasskeyPurpose,
  kind?: 'create' | 'get'
): Promise<void>;
