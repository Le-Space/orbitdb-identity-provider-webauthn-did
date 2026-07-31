import adapter from '@sveltejs/adapter-static';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  kit: {
    adapter: adapter(),
    // Shared demo chrome lives one level up so the three demos cannot drift
    // apart again; see examples/shared/.
    alias: { $shared: '../shared' },
  },
};

export default config;
