import type { PasskeyStep } from './passkey-steps';

export interface PasskeyPurposeText {
  title: string;
  why: string;
}

export interface PasskeyStepStrings {
  count: string;
  countOpen: string;
  notALoop: string;
  continue: string;
  cancel: string;
  purposes: Record<string, PasskeyPurposeText>;
}

/** Built-in wording, German and English. */
export const PASSKEY_STEP_STRINGS: Record<'en' | 'de', PasskeyStepStrings>;

/** `<passkey-step-dialog>`: between two passkey prompts, what the next one is for. */
export class PasskeyStepDialogElement extends HTMLElement {
  /** Replace built-in wording per language, or add a language. */
  strings: Partial<Record<string, Partial<PasskeyStepStrings>>>;
  /** This element's `lang`, then the document's. */
  readonly language: string;
  /** Whether a step is showing. */
  readonly isOpen: boolean;
  /** Show the step; resolves on "Continue", rejects with PasskeyStepCancelled otherwise. */
  ask(step: PasskeyStep): Promise<void>;
}

/** Make this element the handler for every announced passkey prompt. */
export function connectPasskeyStepDialog(
  element: PasskeyStepDialogElement
): () => void;

export {
  setPasskeyStepHandler,
  withPasskeySteps,
  PasskeyStepCancelled,
  PASSKEY_PURPOSES,
} from './passkey-steps';
export type { PasskeyStep, PasskeyPurpose } from './passkey-steps';

declare global {
  interface HTMLElementTagNameMap {
    'passkey-step-dialog': PasskeyStepDialogElement;
  }
}
