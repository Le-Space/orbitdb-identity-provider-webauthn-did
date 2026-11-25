/**
 * Before a passkey prompt, a word on what it is for — when an application asks
 * for one.
 *
 * Creating a passkey-backed identity asks the authenticator three times in a
 * row: the passkey itself, the PRF output the signing key comes from, and the
 * signature on the identity. Restoring one from the authenticator asks three
 * times as well. Without a word in between, that looks like a loop, and people
 * cancel it. Le-Space/belege put a dialog between its prompts (#429); every
 * other application would have had to rebuild it, and only this package knows
 * when it is about to ask and why.
 *
 * So every WebAuthn call in this package first awaits
 * {@link beforePasskeyCeremony} with its purpose. An application that wants
 * the word in between registers a handler and declares how many prompts an
 * action takes:
 *
 * ```js
 * setPasskeyStepHandler((step) => dialog.ask(step)) // resolve = go on, throw = stop
 * await withPasskeySteps(3, async () => {
 *   const credential = await WebAuthnDIDProvider.createCredential(...) // 1 of 3
 *   await startOrbitDB(credential)                                     // 2 and 3 of 3
 * })
 * ```
 *
 * The first prompt of a plan is not announced: it comes from the click that
 * started the action. Every later one is, and it starts from the click that
 * answers the handler — which is also what Safari wants, a user gesture for
 * each WebAuthn call.
 *
 * Without a handler, or outside a plan, nothing changes: every call goes
 * straight to the authenticator, as before.
 *
 * `<passkey-step-dialog>` in `./elements` is a handler that needs no
 * framework.
 */

/**
 * Why the authenticator is being asked. The dialog's wording is keyed on it.
 *
 * - `create` — a new passkey
 * - `signing-key` — the PRF output the signing key is derived from
 * - `identity` — the passkey signs the identity once
 * - `restore` — find a passkey this device has nothing stored for
 * - `restore-confirm` — the same passkey again: two signatures recover its key
 * - `keystore` — seal or open the keystore's key with the passkey
 * - `prf` — a secret from the passkey, for the application's own key
 * - `metadata` — details the passkey carries for this application
 * - `wallet` — the passkey signs for the account
 * - `sign-entry` — the passkey signs an entry itself (varsig)
 *
 * @typedef {'create' | 'signing-key' | 'identity' | 'restore' | 'restore-confirm'
 *   | 'keystore' | 'prf' | 'metadata' | 'wallet' | 'sign-entry'} PasskeyPurpose
 */

/** @type {ReadonlyArray<PasskeyPurpose>} */
export const PASSKEY_PURPOSES = Object.freeze([
  'create',
  'signing-key',
  'identity',
  'restore',
  'restore-confirm',
  'keystore',
  'prf',
  'metadata',
  'wallet',
  'sign-entry',
]);

/**
 * What a handler is told: which prompt comes next, and why. `of` is null when
 * the plan did not say how many there are.
 *
 * @typedef {{ purpose: PasskeyPurpose, n: number, of: number | null,
 *   kind: 'create' | 'get' }} PasskeyStep
 */

/** Thrown when somebody stops between two prompts. Nothing has been asked yet. */
export class PasskeyStepCancelled extends Error {
  constructor(message = 'The passkey prompt was cancelled before it started.') {
    super(message);
    this.name = 'PasskeyStepCancelled';
  }
}

/** @type {((step: PasskeyStep) => unknown) | null} */
let handler = null;

/**
 * The plans of the actions running now, latest last. Usually one: WebAuthn
 * allows one ceremony at a time. But two actions can overlap while neither is
 * in a ceremony — both waiting on the network, say — and then each has to
 * leave without disturbing the other's plan.
 * @type {Array<{ of: number | null, n: number, askFirst: boolean }>}
 */
const plans = [];

/**
 * Register what runs before each announced prompt, or `null` to stop.
 *
 * The handler resolves to let the prompt go ahead and throws to stop it — a
 * {@link PasskeyStepCancelled}, ideally, which then reaches the caller of the
 * action unchanged.
 *
 * @param {((step: PasskeyStep) => unknown) | null} next
 * @returns {() => void} unregisters this handler, if it is still the one
 */
export function setPasskeyStepHandler(next) {
  const mine = typeof next === 'function' ? next : null;
  handler = mine;
  return () => {
    if (handler === mine) handler = null;
  };
}

/**
 * Run an action whose passkey prompts are numbered.
 *
 * `of` is how many prompts the action takes, as the application counts them
 * (escrow01: 3 to create a passkey, 3 to restore one, 1 to come back with a
 * stored one). A number that turns out too small does no harm beyond the
 * dialog saying "4 of 3": the count is the application's promise, and its
 * tests are where it is kept.
 *
 * `askFirst` announces the first prompt too, for an action that does not start
 * from a click of its own.
 *
 * Plans do not nest: the inner one numbers its own prompts and the outer one
 * resumes afterwards. Two actions that overlap each leave their own plan
 * when they end, whichever ends first. A prompt counts towards the plan that
 * started last; nothing tells which action a prompt belongs to, so a prompt
 * made outside the action (a background signature, say) while it runs is
 * counted as one of its own.
 *
 * @template T
 * @param {number | null | { of?: number | null, askFirst?: boolean }} options
 * @param {() => Promise<T> | T} run
 * @returns {Promise<T>}
 */
export async function withPasskeySteps(options, run) {
  const { of = null, askFirst = false } =
    typeof options === 'number' || options === null
      ? { of: options }
      : (options ?? {});
  const mine = {
    of: typeof of === 'number' && of > 0 ? of : null,
    n: 0,
    askFirst,
  };
  plans.push(mine);
  try {
    return await run();
  } finally {
    // Its own plan, wherever it is now: an action that started later and is
    // still running keeps its plan.
    plans.splice(plans.lastIndexOf(mine), 1);
  }
}

/**
 * Called by this package — and by an application, around its own WebAuthn
 * calls — right before the authenticator is asked.
 *
 * Outside a plan, or without a handler, it returns at once. Inside one it
 * counts the prompt and, from the second on (or from the first, with
 * `askFirst`), waits for the handler.
 *
 * Call it outside any `try` that turns a failed ceremony into a fallback: a
 * cancel has to reach the person's action, not be read as "this
 * authenticator cannot".
 *
 * @param {PasskeyPurpose} purpose
 * @param {'create' | 'get'} [kind]
 * @returns {Promise<void>}
 */
export async function beforePasskeyCeremony(purpose, kind = 'get') {
  const plan = plans[plans.length - 1];
  if (!plan) return;
  plan.n += 1;
  if (!handler) return;
  if (plan.n === 1 && !plan.askFirst) return;
  await handler({ purpose, n: plan.n, of: plan.of, kind });
}
