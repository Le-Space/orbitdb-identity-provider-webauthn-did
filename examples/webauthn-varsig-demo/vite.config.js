import { sveltekit } from '@sveltejs/kit/vite';
import { createLogger, defineConfig } from 'vite';
import { nodePolyfills } from 'vite-plugin-node-polyfills';
import { fileURLToPath } from 'url';
import { readFileSync } from 'fs';

// update version in package.json and title
const repoRootDir = fileURLToPath(new URL('../..', import.meta.url));
const file = fileURLToPath(new URL('package.json', import.meta.url));
const json = readFileSync(file, 'utf8');
const pkg = JSON.parse(json);

// Create build date
const buildDate =
  new Date().toISOString().split('T')[0] +
  ' ' +
  new Date().toLocaleTimeString(); // YYYY-MM-DD HH:MM:SS format

function suppressKnownPolyfillWarnings(warning, warn) {
  if (
    warning.message.includes(
      '"default" is imported from external module "vite-plugin-node-polyfills/shims/global"'
    )
  ) {
    return;
  }

  warn(warning);
}

const logger = createLogger();
const warn = logger.warn;
logger.warn = (message, options) => {
  if (
    message.includes(
      '"default" is imported from external module "vite-plugin-node-polyfills/shims/global"'
    )
  ) {
    return;
  }

  warn(message, options);
};

export default defineConfig({
  resolve: {
    alias: {
      // $shared/ lives outside this package, so bare imports inside it would
      // resolve from examples/, which has no node_modules. Point Carbon at this
      // demo's own copy; there is no workspace to hoist it into.
      'carbon-components-svelte': fileURLToPath(
        new URL('node_modules/carbon-components-svelte', import.meta.url)
      ),
      'carbon-icons-svelte': fileURLToPath(
        new URL('node_modules/carbon-icons-svelte', import.meta.url)
      ),
    },
  },
  customLogger: logger,
  // $shared resolves outside the app root, which vite dev blocks by default.
  // The sibling demos already allow the repo root; match them.
  server: { fs: { allow: [repoRootDir] } },
  plugins: [
    sveltekit(),
    nodePolyfills({
      include: [
        'path',
        'util',
        'buffer',
        'process',
        'events',
        'crypto',
        'os',
        'stream',
        'string_decoder',
      ],
      globals: {
        Buffer: true,
        global: true,
        process: true,
      },
      protocolImports: true,
    }),
  ],
  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
    __BUILD_DATE__: JSON.stringify(buildDate),
  },
  build: {
    chunkSizeWarningLimit: 2500,
    rollupOptions: {
      onwarn: suppressKnownPolyfillWarnings,
    },
  },
});
