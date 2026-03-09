<script>
  import MultiDeviceApp from '$lib/MultiDeviceApp.svelte';
  import { theme } from '$lib/theme.js';
  import {
    Content,
    Header,
    HeaderUtilities,
    Button,
  } from 'carbon-components-svelte';
  import { Light, Asleep } from 'carbon-icons-svelte';
  import { onMount } from 'svelte';

  onMount(() => {
    const particlesContainer = document.querySelector('.particles');
    if (particlesContainer) {
      for (let i = 0; i < 30; i++) {
        const particle = document.createElement('div');
        particle.className = 'particle';
        particle.style.left = Math.random() * 100 + '%';
        particle.style.animationDelay = Math.random() * 15 + 's';
        particle.style.animationDuration = 15 + Math.random() * 10 + 's';
        particlesContainer.appendChild(particle);
      }
    }
  });

  function toggleTheme() {
    theme.toggle();
  }

  $: isDark = $theme === 'g100';
</script>

<svelte:head>
  <title>OrbitDB Multi-Device WebAuthn Demo</title>
  <meta
    name="description"
    content="Multi-device linking and recovery demo for OrbitDB with WebAuthn biometric credentials"
  />
</svelte:head>

<div class="particles"></div>

<Header company="OrbitDB Multi-Device Demo">
  <HeaderUtilities>
    <Button
      kind="ghost"
      size="small"
      icon={isDark ? Light : Asleep}
      iconDescription={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
      on:click={toggleTheme}
    >
      {isDark ? 'Light' : 'Dark'}
    </Button>
  </HeaderUtilities>
</Header>

<Content>
  <div style="display:flex;justify-content:center;margin:2rem 0 1rem;">
    <div style="text-align:center;">
      <h1 class="gradient-text-purple" style="margin:0 0 0.5rem;">
        Multi-Device OrbitDB
      </h1>
      <p style="color:var(--cds-text-secondary);margin:0;">
        Link devices & recover access using WebAuthn biometric credentials
      </p>
    </div>
  </div>

  <div class="orbital-card" style="border-radius:1rem;padding:1.5rem;">
    <MultiDeviceApp />
  </div>

  <div style="text-align:center;margin:2rem 0;color:var(--cds-text-secondary);">
    <small>OrbitDB Multi-Device Demo — libp2p + WebAuthn + OrbitDBAccessController</small>
  </div>
</Content>
