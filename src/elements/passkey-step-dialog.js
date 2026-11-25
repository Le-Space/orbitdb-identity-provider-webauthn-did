/**
 * `<passkey-step-dialog>`: between two passkey prompts, what the next one is
 * for, and "Continue" to start it.
 *
 * A handler for {@link setPasskeyStepHandler} that needs no framework. It was
 * Le-Space/belege's `PasskeyStepDialog.svelte` (#429) first; this is the same
 * dialog for every application that uses this package.
 *
 * ```html
 * <passkey-step-dialog></passkey-step-dialog>
 * <script type="module">
 *   import { connectPasskeyStepDialog } from '@le-space/orbitdb-identity-provider-webauthn-did/elements'
 *   connectPasskeyStepDialog(document.querySelector('passkey-step-dialog'))
 * </script>
 * ```
 *
 * The language follows the element's `lang`, then the document's; German and
 * English are built in. `strings` replaces any of them, per language — an
 * application's own words for a purpose, or a language of its own.
 *
 * Its colours come from custom properties, so it sits in an application's
 * theme instead of next to it: `--passkey-step-background`, `-color`,
 * `-muted`, `-border`, `-accent`, `-on-accent`, `-radius`, `-backdrop`.
 */
import { PasskeyStepCancelled } from '../passkey-steps.js';

/**
 * @typedef {{ title: string, why: string }} PurposeText
 * @typedef {{ count: string, countOpen: string, notALoop: string,
 *   continue: string, cancel: string,
 *   purposes: Record<string, PurposeText> }} PasskeyStepStrings
 */

/** @type {Record<'en' | 'de', PasskeyStepStrings>} */
export const PASSKEY_STEP_STRINGS = {
  en: {
    count: 'Passkey prompt {n} of {of}',
    countOpen: 'Passkey prompt {n}',
    notALoop:
      'Each prompt has its own purpose; it is not a repeat. With a security key: touch it and, if asked, enter its PIN.',
    continue: 'Continue',
    cancel: 'Cancel',
    purposes: {
      create: {
        title: 'Now create your passkey',
        why: 'Your device creates a passkey for this app, with Touch ID or your PIN for example.',
      },
      'signing-key': {
        title: 'Now the key that signs your entries',
        why: 'Your passkey gives the app a secret. The key that signs what you write comes from it, so the same passkey signs as you on every device.',
      },
      identity: {
        title: 'Now confirm your identity',
        why: 'The passkey signs your identity, so other devices can check that your entries come from you.',
      },
      restore: {
        title: 'Now find your passkey',
        why: 'This device has nothing stored for it. Your device or password manager offers the passkey, and the app recovers your identity from its answer.',
      },
      'restore-confirm': {
        title: 'Once more, the same passkey',
        why: 'A passkey’s public key is recovered from two signatures. The second one confirms which key is yours.',
      },
      keystore: {
        title: 'Now your sealed keys',
        why: 'The keys this app keeps on this device are sealed with your passkey: it seals them, or opens them for this visit.',
      },
      prf: {
        title: 'Now the key for your data',
        why: 'Your passkey gives the app a secret, and the key for your data comes from it.',
      },
      metadata: {
        title: 'Now the details your passkey carries',
        why: 'The passkey keeps a few details for this app, so another device can find your identity.',
      },
      wallet: {
        title: 'Now confirm with your passkey',
        why: 'The passkey signs a request for your account. Without it, nothing is moved.',
      },
      'sign-entry': {
        title: 'Now sign this entry',
        why: 'Here the passkey signs each entry itself.',
      },
    },
  },
  de: {
    count: 'Passkey-Abfrage {n} von {of}',
    countOpen: 'Passkey-Abfrage {n}',
    notALoop:
      'Jede Abfrage hat ihren eigenen Zweck, es ist keine Wiederholung. Mit einem Sicherheitsschlüssel: berühren und, falls gefragt, die PIN eingeben.',
    continue: 'Weiter',
    cancel: 'Abbrechen',
    purposes: {
      create: {
        title: 'Jetzt Ihren Passkey anlegen',
        why: 'Ihr Gerät legt einen Passkey für diese App an, zum Beispiel mit Touch ID oder Ihrer PIN.',
      },
      'signing-key': {
        title: 'Jetzt der Schlüssel, der Ihre Einträge unterschreibt',
        why: 'Ihr Passkey gibt der App ein Geheimnis. Daraus entsteht der Schlüssel, der unterschreibt, was Sie schreiben – so unterschreibt derselbe Passkey auf jedem Gerät als Sie.',
      },
      identity: {
        title: 'Jetzt Ihre Identität bestätigen',
        why: 'Der Passkey unterschreibt Ihre Identität. So können andere Geräte prüfen, dass Ihre Einträge von Ihnen stammen.',
      },
      restore: {
        title: 'Jetzt Ihren Passkey finden',
        why: 'Auf diesem Gerät ist dafür nichts gespeichert. Ihr Gerät oder Passwortmanager bietet den Passkey an, und aus seiner Antwort stellt die App Ihre Identität wieder her.',
      },
      'restore-confirm': {
        title: 'Noch einmal derselbe Passkey',
        why: 'Der öffentliche Schlüssel eines Passkeys ergibt sich aus zwei Unterschriften. Die zweite bestätigt, welcher Schlüssel Ihrer ist.',
      },
      keystore: {
        title: 'Jetzt Ihre versiegelten Schlüssel',
        why: 'Die Schlüssel, die diese App auf diesem Gerät aufbewahrt, sind mit Ihrem Passkey versiegelt: Er versiegelt sie oder öffnet sie für diesen Besuch.',
      },
      prf: {
        title: 'Jetzt der Schlüssel für Ihre Daten',
        why: 'Ihr Passkey gibt der App ein Geheimnis, und daraus entsteht der Schlüssel für Ihre Daten.',
      },
      metadata: {
        title: 'Jetzt die Angaben, die Ihr Passkey mitführt',
        why: 'Der Passkey bewahrt ein paar Angaben für diese App auf, damit ein anderes Gerät Ihre Identität findet.',
      },
      wallet: {
        title: 'Jetzt mit dem Passkey bestätigen',
        why: 'Der Passkey unterschreibt eine Anfrage für Ihr Konto. Ohne ihn wird nichts bewegt.',
      },
      'sign-entry': {
        title: 'Jetzt diesen Eintrag unterschreiben',
        why: 'Hier unterschreibt der Passkey jeden Eintrag selbst.',
      },
    },
  },
};

const STYLE = `
  :host {
    --_bg: var(--passkey-step-background, #ffffff);
    --_fg: var(--passkey-step-color, #1b2230);
    --_muted: var(--passkey-step-muted, #5b6577);
    --_border: var(--passkey-step-border, #d6dce6);
    --_accent: var(--passkey-step-accent, #cf3f30);
    --_on-accent: var(--passkey-step-on-accent, #ffffff);
    --_radius: var(--passkey-step-radius, 14px);
  }
  @media (prefers-color-scheme: dark) {
    :host {
      --_bg: var(--passkey-step-background, #12161f);
      --_fg: var(--passkey-step-color, #e8ecf3);
      --_muted: var(--passkey-step-muted, #97a1b3);
      --_border: var(--passkey-step-border, rgba(255, 255, 255, 0.14));
    }
  }
  dialog {
    box-sizing: border-box;
    width: calc(100vw - 2rem);
    max-width: 28rem;
    max-height: calc(100dvh - 2rem);
    overflow: auto;
    margin: auto;
    padding: 1.25rem;
    border: 1px solid var(--_border);
    border-radius: var(--_radius);
    background: var(--_bg);
    color: var(--_fg);
    font: inherit;
  }
  dialog::backdrop { background: var(--passkey-step-backdrop, rgba(0, 0, 0, 0.55)); }
  .count {
    margin: 0; font-size: 0.75rem; font-weight: 600;
    letter-spacing: 0.04em; text-transform: uppercase; color: var(--_muted);
  }
  h2 { margin: 0.25rem 0 0; font-size: 1.125rem; line-height: 1.35; }
  p.why { margin: 0.5rem 0 0; line-height: 1.5; font-size: 0.95rem; }
  p.loop { margin: 0.5rem 0 0; line-height: 1.5; font-size: 0.875rem; color: var(--_muted); }
  .actions { display: flex; flex-wrap: wrap; justify-content: flex-end; gap: 0.5rem; margin-top: 1rem; }
  button {
    min-height: 2.75rem; padding: 0 1rem; border-radius: 0.375rem;
    font: inherit; font-size: 0.9rem; cursor: pointer;
  }
  button[part="cancel"] { background: transparent; color: var(--_fg); border: 1px solid var(--_border); }
  button[part="continue"] { background: var(--_accent); color: var(--_on-accent); border: 1px solid transparent; font-weight: 600; }
  button:focus-visible { outline: 2px solid var(--_accent); outline-offset: 2px; }
`;

/**
 * @param {string} template
 * @param {Record<string, string | number>} values
 */
const fill = (template, values) =>
  template.replace(/\{(\w+)\}/g, (whole, key) =>
    key in values ? String(values[key]) : whole
  );

/**
 * Where there is no DOM — a server-side render importing ./elements — the
 * class is still defined, on a stand-in, so that the import does not throw.
 * It is only registered where there is a customElements registry.
 */
const Base = /** @type {typeof HTMLElement} */ (
  globalThis.HTMLElement ?? class {}
);

/**
 * How long "Continue" ignores clicks and key presses after a step appears,
 * in milliseconds: the second click of a double click, or a held Enter,
 * meant for the step before, must not approve this one unread.
 */
export const CONTINUE_DELAY_MS = 400;

export class PasskeyStepDialogElement extends Base {
  /** @type {Partial<Record<string, Partial<PasskeyStepStrings>>>} */
  #overrides = {};
  /** @type {{ resolve: () => void, reject: (error: Error) => void } | null} */
  #pending = null;
  /** When the step on screen appeared (`performance.now()`). */
  #shownAt = 0;

  constructor() {
    super();
    const root = this.attachShadow({ mode: 'open' });
    root.innerHTML = `<style>${STYLE}</style>
      <dialog part="dialog" aria-labelledby="title" aria-describedby="why">
        <p class="count" part="count"></p>
        <h2 id="title" part="title"></h2>
        <p id="why" class="why" part="why"></p>
        <p class="loop" part="loop"></p>
        <div class="actions">
          <button type="button" part="cancel"></button>
          <button type="button" part="continue" autofocus></button>
        </div>
      </dialog>`;
    this.dialog = /** @type {HTMLDialogElement} */ (
      root.querySelector('dialog')
    );
    root.querySelector('[part=continue]').addEventListener('click', () => {
      if (performance.now() - this.#shownAt < CONTINUE_DELAY_MS) return;
      this.#settle(null);
    });
    root
      .querySelector('[part=cancel]')
      .addEventListener('click', () =>
        this.#settle(new PasskeyStepCancelled())
      );
    // Escape is "Cancel", not a silent close that leaves the action waiting.
    this.dialog.addEventListener('cancel', (event) => {
      event.preventDefault();
      this.#settle(new PasskeyStepCancelled());
    });
    // Closed some other way — `dialog.close()` from the page, say — the step
    // is not answered "Continue". A close that a new step has already
    // reopened (`#settle` closes, `ask` opens again) is not one.
    this.dialog.addEventListener('close', () => {
      if (!this.dialog.open) this.#settle(new PasskeyStepCancelled());
    });
  }

  /**
   * Replace built-in wording, per language: `{ de: { purposes: { prf: { title,
   * why } } } }`, or a language of its own with every key.
   *
   * @param {Partial<Record<string, Partial<PasskeyStepStrings>>>} value
   */
  set strings(value) {
    this.#overrides = value ?? {};
  }

  get strings() {
    return this.#overrides;
  }

  /** The language on screen: this element's `lang`, then the document's. */
  get language() {
    const declared = (
      this.getAttribute('lang') ||
      this.closest('[lang]')?.getAttribute('lang') ||
      document.documentElement.lang ||
      'en'
    )
      .slice(0, 2)
      .toLowerCase();
    return declared;
  }

  /** @returns {PasskeyStepStrings} */
  #text() {
    const language = this.language;
    const base = PASSKEY_STEP_STRINGS[language] ?? PASSKEY_STEP_STRINGS.en;
    const own = this.#overrides[language] ?? {};
    return {
      ...base,
      ...own,
      purposes: { ...base.purposes, ...(own.purposes ?? {}) },
    };
  }

  /**
   * Show the step and wait. Resolves on "Continue"; rejects with
   * {@link PasskeyStepCancelled} on "Cancel" or Escape.
   *
   * @param {import('../passkey-steps.js').PasskeyStep} step
   * @returns {Promise<void>}
   */
  ask(step) {
    // A step that is still open is answered "cancel" first: two prompts at
    // once are not possible, so an older one is a leftover.
    this.#settle(new PasskeyStepCancelled());

    const text = this.#text();
    const purpose = text.purposes[step.purpose] ?? {
      title: step.purpose,
      why: '',
    };
    const root = /** @type {ShadowRoot} */ (this.shadowRoot);
    root.querySelector('[part=count]').textContent =
      typeof step.of === 'number'
        ? fill(text.count, { n: step.n, of: step.of })
        : fill(text.countOpen, { n: step.n });
    root.querySelector('[part=title]').textContent = purpose.title;
    root.querySelector('[part=why]').textContent = purpose.why;
    root.querySelector('[part=loop]').textContent = text.notALoop;
    root.querySelector('[part=continue]').textContent = text.continue;
    root.querySelector('[part=cancel]').textContent = text.cancel;
    this.setAttribute('data-purpose', step.purpose);

    return new Promise((resolve, reject) => {
      try {
        if (!this.dialog.open) this.dialog.showModal();
      } catch (error) {
        // Not on the page, for one: nothing is waiting, and nothing is left
        // marked as if it were.
        this.removeAttribute('data-purpose');
        reject(error);
        return;
      }
      this.#pending = { resolve, reject };
      this.#shownAt = performance.now();
      /** @type {HTMLElement} */ (
        root.querySelector('[part=continue]')
      ).focus();
    });
  }

  /** Whether a step is showing. */
  get isOpen() {
    return this.dialog.open;
  }

  /** @param {Error | null} error */
  #settle(error) {
    const pending = this.#pending;
    if (!pending) return;
    this.#pending = null;
    this.removeAttribute('data-purpose');
    if (this.dialog.open) this.dialog.close();
    if (error) pending.reject(error);
    else pending.resolve();
  }

  disconnectedCallback() {
    // Taken off the page while it waits: nothing can answer it any more.
    this.#settle(new PasskeyStepCancelled());
  }
}
