<script>
  // The whole page frame — header, switcher, hero, footer — lives in the shared
  // DemoShell; this file is only "which demo is this, and what goes in it".
  import WebAuthnTodo from '$lib/WebAuthnTodo.svelte';
  import DemoShell from '$shared/DemoShell.svelte';
  import { demoById } from '$shared/demos.js';
</script>

<DemoShell demo={demoById('ed25519-encrypted-keystore-demo')}>
  <WebAuthnTodo />
</DemoShell>
