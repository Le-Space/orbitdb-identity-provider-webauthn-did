<script>
  // Carbon's stylesheet was never imported, so every Carbon component in
  // these demos rendered unstyled — the header stacked, buttons were bare
  // links, and the theme store's `theme` attribute had nothing to drive.
  // all.css carries every theme and switches on that attribute.
  import 'carbon-components-svelte/css/all.css';
  import '../app.css';
  import { theme } from '$lib/theme.js';
  import { onMount } from 'svelte';

  onMount(() => {
    theme.init();
  });
</script>

<div class="app">
  <slot />
</div>
