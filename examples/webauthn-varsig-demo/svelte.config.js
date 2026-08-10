import adapter from '@sveltejs/adapter-static';

/** @type {import('@sveltejs/kit').Config} */
const config = {
  kit: {
    adapter: adapter(),
    // Shared demo chrome lives one level up so the three demos cannot drift
    // apart again; see examples/shared/.
    alias: { $shared: '../shared' },
    prerender: {
      // The switcher links to the sibling demos, which are separate builds
      // deployed next to this one on Pages. The prerenderer cannot resolve
      // them and must not treat that as a broken link.
      handleHttpError: ({ path, message }) => {
        if (/^\/(webauthn-todo-demo|ed25519-encrypted-keystore-demo|webauthn-varsig-demo)\//.test(path)) return;
        throw new Error(message);
      },
    },
  },
};

export default config;
