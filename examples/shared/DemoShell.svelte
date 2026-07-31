<script>
  /**
   * Everything the three demos have in common: Carbon header with the Le-Space
   * lockup and theme toggle, the switcher nav, the hero, the technology row and
   * the footer. The demo's own body goes in the slot.
   *
   * This replaces three 270-line pages that differed in about ten strings —
   * which is how the encrypted-keystore demo ended up shipping the WebAuthn DID
   * demo's title, and how each demo's switcher nav came to list a different
   * subset of its siblings.
   */
  import { Content, Header, HeaderUtilities, Button } from 'carbon-components-svelte';
  import { Light, Asleep } from 'carbon-icons-svelte';
  import { onMount } from 'svelte';
  import { theme } from '$lib/theme.js';
  import LeSpaceBrand from '$shared/LeSpaceBrand.svelte';
  import { demos } from '$shared/demos.js';

  /** @type {import('./demos.js').demos[number]} */
  export let demo;

  const others = demos.filter((d) => d.id !== demo.id);

  const TECH = [
    { href: 'https://orbitdb.org/', img: './orbitdb.png', label: 'OrbitDB' },
    { href: 'https://w3c.github.io/webauthn/', emoji: '🔐', label: null },
    { href: 'https://helia.io/', img: './helia.svg', label: 'Helia' },
    { href: 'https://docs.ipfs.tech/', img: './ipfs.png', label: 'IPFS' },
    { href: 'https://docs.libp2p.io/', img: './libp2p.png', label: 'libp2p' },
  ];

  onMount(() => {
    const particlesContainer = document.querySelector('.particles');
    if (!particlesContainer) return;
    for (let i = 0; i < 50; i++) {
      const particle = document.createElement('div');
      particle.className = 'particle';
      particle.style.left = Math.random() * 100 + '%';
      particle.style.animationDelay = Math.random() * 15 + 's';
      particle.style.animationDuration = 15 + Math.random() * 10 + 's';
      particlesContainer.appendChild(particle);
    }
  });

  $: isDark = $theme === 'g100';
</script>

<svelte:head>
  <title>{demo.title}</title>
  <meta name="description" content={demo.description} />
</svelte:head>

<div class="particles"></div>

<Header company={demo.company}>
  <HeaderUtilities>
    <LeSpaceBrand />
    <Button
      kind="ghost"
      size="small"
      icon={isDark ? Light : Asleep}
      iconDescription={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
      on:click={() => theme.toggle()}
    >
      {isDark ? 'Light' : 'Dark'}
    </Button>
  </HeaderUtilities>
</Header>

<Content>
  <nav aria-label="Demo switcher" class="switcher">
    <a href="../">All demos</a>
    {#each others as other (other.id)}
      <a href="../{other.id}/">{other.nav}</a>
    {/each}
  </nav>

  <div class="hero">
    <div>
      <div class="hero-logo">
        <svg xmlns="http://www.w3.org/2000/svg" width="120" height="120" viewBox="0 0 32 32">
          <defs>
            <linearGradient id="orbitGradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" style="stop-color:#4F46E5;stop-opacity:1" />
              <stop offset="100%" style="stop-color:#7C3AED;stop-opacity:1" />
            </linearGradient>
            <linearGradient id="storageGradient" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" style="stop-color:#06B6D4;stop-opacity:1" />
              <stop offset="100%" style="stop-color:#0891B2;stop-opacity:1" />
            </linearGradient>
          </defs>
          <circle
            cx="16"
            cy="16"
            r="15"
            fill="var(--cds-layer)"
            stroke="var(--cds-border-subtle)"
            stroke-width="1"
          />
          <circle cx="16" cy="16" r="4" fill="url(#storageGradient)" />
          <g class="orbit-animation" style="transform-origin: 16px 16px;">
            <ellipse cx="16" cy="16" rx="10" ry="6" fill="none" stroke="url(#orbitGradient)" stroke-width="1.5" opacity="0.8" />
            <ellipse cx="16" cy="16" rx="6" ry="10" fill="none" stroke="url(#orbitGradient)" stroke-width="1.5" opacity="0.8" />
            <circle cx="26" cy="16" r="1.5" fill="url(#orbitGradient)" />
            <circle cx="6" cy="16" r="1.5" fill="url(#orbitGradient)" />
            <circle cx="16" cy="6" r="1.5" fill="url(#orbitGradient)" />
            <circle cx="16" cy="26" r="1.5" fill="url(#orbitGradient)" />
          </g>
          <path d="M12 12 Q10 10 8 12 Q6 14 8 16 Q10 18 12 16 Q14 14 12 12" fill="url(#storageGradient)" opacity="0.6" />
          <path d="M20 20 Q22 18 24 20 Q26 22 24 24 Q22 26 20 24 Q18 22 20 20" fill="url(#storageGradient)" opacity="0.6" />
        </svg>
      </div>

      <h1 class="gradient-text-purple hero-title">{demo.heading}</h1>
      <p class="hero-sub">
        local-first peer-to-peer todo example with
        <span class="gradient-text-cyan" style="font-weight:600;">{demo.highlight}</span>
      </p>
      <p class="hero-note">data stored in browser IndexedDB via OrbitDB</p>

      <div class="tech">
        {#each TECH as t (t.href)}
          <a href={t.href} target="_blank" rel="noopener noreferrer">
            {#if t.img}
              <img src={t.img} alt={t.label} />
            {:else}
              <span class="tech-emoji">{t.emoji}</span>
            {/if}
            <span class="tech-label">{t.label ?? demo.techLabel}</span>
          </a>
        {/each}
      </div>
    </div>
  </div>

  <div class="orbital-card demo-body">
    <slot />
  </div>

  <div class="foot">
    <small>{demo.title}</small>
    <div class="foot-note">{demo.footerNote}</div>
  </div>
</Content>

<style>
  .switcher {
    display: flex;
    justify-content: center;
    gap: 0.75rem;
    margin: 1rem 0 0;
    flex-wrap: wrap;
  }

  .switcher a {
    color: var(--cds-link-primary);
  }

  .hero {
    display: flex;
    justify-content: center;
    margin: 2rem 0;
  }

  .hero-logo {
    display: flex;
    justify-content: center;
    margin-bottom: 1rem;
  }

  .hero-title {
    text-align: center;
    margin: 0 0 0.5rem 0;
  }

  .hero-sub {
    text-align: center;
    margin: 0 0 1rem 0;
    color: var(--cds-text-secondary);
  }

  .hero-note {
    text-align: center;
    color: var(--cds-text-helper);
    font-size: 0.875rem;
  }

  .tech {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 1.5rem;
    margin-top: 1.5rem;
    flex-wrap: wrap;
  }

  .tech a {
    display: flex;
    align-items: center;
    gap: 0.25rem;
    text-decoration: none;
    color: inherit;
  }

  .tech img {
    width: 20px;
    height: 20px;
    object-fit: contain;
  }

  .tech-emoji {
    font-size: 1rem;
  }

  .tech-label {
    font-size: 0.75rem;
    color: var(--cds-text-secondary);
  }

  .demo-body {
    border-radius: 1rem;
    padding: 1rem;
    margin: 0 auto;
  }

  .foot {
    text-align: center;
    margin: 2rem 0;
    color: var(--cds-text-secondary);
  }

  .foot-note {
    margin-top: 0.5rem;
    color: var(--cds-text-helper);
    font-size: 0.75rem;
  }
</style>
