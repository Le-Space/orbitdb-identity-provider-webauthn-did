<script>
  import "../app.css";
  import { theme } from "$lib/theme.js";
  import { onMount } from "svelte";

  onMount(() => {
    theme.init();
  });
</script>

<div class="app">
  <slot />
</div>
