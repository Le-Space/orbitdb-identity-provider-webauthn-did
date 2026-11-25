/**
 * Custom elements, for an application whatever its framework.
 *
 * `<passkey-step-dialog>` says, between two passkey prompts, what the next one
 * is for. {@link connectPasskeyStepDialog} makes an element on the page the
 * handler for every prompt this package announces.
 */
import { setPasskeyStepHandler } from '../passkey-steps.js';
import {
  CONTINUE_DELAY_MS,
  PasskeyStepDialogElement,
  PASSKEY_STEP_STRINGS,
} from './passkey-step-dialog.js';

if (
  globalThis.customElements &&
  !globalThis.customElements.get('passkey-step-dialog')
) {
  globalThis.customElements.define(
    'passkey-step-dialog',
    PasskeyStepDialogElement
  );
}

/**
 * Let this element answer every announced passkey prompt.
 *
 * @param {PasskeyStepDialogElement} element
 * @returns {() => void} disconnects it again (if it is still the handler)
 */
export function connectPasskeyStepDialog(element) {
  return setPasskeyStepHandler((step) => element.ask(step));
}

export { CONTINUE_DELAY_MS, PasskeyStepDialogElement, PASSKEY_STEP_STRINGS };
export {
  setPasskeyStepHandler,
  withPasskeySteps,
  PasskeyStepCancelled,
  PASSKEY_PURPOSES,
} from '../passkey-steps.js';
