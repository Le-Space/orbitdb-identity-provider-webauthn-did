<script>
  // The whole page frame — header, switcher, hero, footer — lives in the shared
  // DemoShell; this file is only "which demo is this, and what goes in it".
  import { browser } from '$app/environment';
  import DemoShell from '$shared/DemoShell.svelte';
  import { demoById } from '$shared/demos.js';

  // Loaded in the browser only. The demo builds a libp2p/Helia node, and
  // importing it at module scope drags @libp2p/webrtc — and its native
  // node-datachannel binding — into the SSR pass, where the dev server 500s on
  // `Cannot find module '.../node_datachannel.node'`. Nothing is lost: the
  // shell carries the title, description and hero that prerendering is for,
  // and this component has nothing to render until there is a browser.
  const todo = browser
    ? import('$lib/WebAuthnTodo.svelte').then((m) => m.default)
    : null;
</script>

<DemoShell demo={demoById('webauthn-todo-demo')}>
  {#if todo}
    {#await todo then WebAuthnTodo}
      <WebAuthnTodo />
    {/await}
  {/if}
</DemoShell>
