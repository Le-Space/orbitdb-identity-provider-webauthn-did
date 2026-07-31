<script>
  /**
   * Le-Space brand lockup plus a link back to the repository, for the demo
   * headers. The demos are published under le-space.de's umbrella but carried
   * no logo and no way back to the source, so a visitor arriving from a search
   * result had no idea whose demo they were looking at.
   *
   * Shared by all three demos via the `$shared` alias (see svelte.config.js)
   * rather than copied into each — the copies are what let them drift apart in
   * the first place.
   *
   * The mark is inlined from docs/le-space-brand/logo/svg/le-space-mark-dark.svg
   * in the landing repo; it is two-colour and works on Carbon's g100 and g10.
   */
  export let repo = 'https://github.com/Le-Space/orbitdb-identity-provider-webauthn-did';
  export let site = 'https://local-first.le-space.de';
</script>

<div class="ls-brand">
  <a class="ls-lockup" href={site} target="_blank" rel="noopener noreferrer" title="Le-Space — the local-first peer-to-peer stack">
    <svg viewBox="0 0 96 96" width="26" height="26" aria-hidden="true">
      <line x1="42.7" y1="49.96" x2="58.56" y2="34.94" stroke="#58C7F3" stroke-width="4" stroke-linecap="round" />
      <line x1="47.43" y1="63.58" x2="62.8" y2="64.98" stroke="#58C7F3" stroke-width="4" stroke-linecap="round" stroke-dasharray="0.1 8" />
      <circle cx="30" cy="62" r="15" fill="#FF6B5B" />
      <circle cx="68" cy="26" r="8" fill="none" stroke="#58C7F3" stroke-width="5" />
      <circle cx="74" cy="66" r="6.5" fill="none" stroke="#58C7F3" stroke-width="4.5" />
    </svg>
    <span class="ls-word">Le-Space</span>
  </a>

  <a class="ls-repo" href={repo} target="_blank" rel="noopener noreferrer" title="Source on GitHub">
    <svg viewBox="0 0 16 16" width="16" height="16" aria-hidden="true" fill="currentColor">
      <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38
        0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01
        1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95
        0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27
        2-.27s1.36.09 2 .27c1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82
        2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0
        .21.15.46.55.38A8.01 8.01 0 0 0 16 8c0-4.42-3.58-8-8-8z" />
    </svg>
    <span>GitHub</span>
  </a>
</div>

<style>
  .ls-brand {
    display: flex;
    align-items: center;
    gap: 14px;
  }

  .ls-lockup,
  .ls-repo {
    display: flex;
    align-items: center;
    gap: 7px;
    text-decoration: none;
    color: inherit;
    opacity: 0.85;
    transition: opacity 0.15s ease;
  }

  .ls-lockup:hover,
  .ls-repo:hover {
    opacity: 1;
  }

  .ls-word {
    font-weight: 600;
    letter-spacing: -0.01em;
    font-size: 0.95rem;
    white-space: nowrap;
  }

  .ls-repo {
    font-size: 0.82rem;
  }

  /* The Carbon header is cramped on phones; the wordmark is the first thing
     that can go, the mark and the repo link both still carry meaning. */
  @media (max-width: 540px) {
    .ls-word {
      display: none;
    }
  }
</style>
