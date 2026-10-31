/**
 * The `./vault` entry stays light: an application that keeps its data outside
 * OrbitDB imports the vault without OrbitDB, ucanto, libp2p or anything else.
 *
 * Walks the entry's import graph from the source, file by file, and fails on
 * the first import of a package — whatever a bundler would make of it.
 */
import { test, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));

/** Every module specifier in a source file: static imports and re-exports. */
function specifiers(source) {
  const found = [];
  const pattern =
    /(?:^|[\s;])(?:import|export)\s[^'"`]*?\sfrom\s*['"]([^'"]+)['"]|(?:^|[\s;])import\s*['"]([^'"]+)['"]|import\(\s*['"]([^'"]+)['"]\s*\)/g;
  for (const match of source.matchAll(pattern)) {
    found.push(match[1] ?? match[2] ?? match[3]);
  }
  return found;
}

/** The files the entry loads, and every package any of them imports. */
function importGraph(entry) {
  const files = new Set();
  const packages = new Set();
  const visit = (file) => {
    if (files.has(file)) return;
    files.add(file);
    for (const specifier of specifiers(readFileSync(file, 'utf8'))) {
      if (specifier.startsWith('.')) visit(resolve(dirname(file), specifier));
      else packages.add(specifier);
    }
  };
  visit(resolve(root, entry));
  return {
    files: [...files].map((f) => f.slice(root.length)),
    packages: [...packages],
  };
}

test('the ./vault entry imports no package at all', () => {
  const entry = pkg.exports['./vault'];
  expect(entry).toEqual({
    types: './types/vault.d.ts',
    import: './src/vault/index.js',
  });

  const { files, packages } = importGraph(entry.import);
  expect(packages).toEqual([]);
  // The keeper, the vault and the PRF keys, and nothing of the provider itself.
  expect(files).toContain('src/keystore/vault-keeper.js');
  expect(files).toContain('src/keystore/vault.js');
  expect(files).toContain('src/keystore/prf-keys.js');
  expect(files.some((f) => /provider|identity|keystore\/index/.test(f))).toBe(
    false
  );
});

test('the walk sees a package import where there is one', () => {
  // The main entry imports OrbitDB's companions; the walk has to notice.
  expect(importGraph('src/index.js').packages.length).toBeGreaterThan(0);
});

test('the ./vault entry offers the vault, its keeper and the PRF keys', async () => {
  const vault = await import('../src/vault/index.js');
  expect(Object.keys(vault).sort()).toEqual(
    [
      'PrfUnavailableError',
      'VaultError',
      'addSlot',
      'createVault',
      'createVaultKeeper',
      'deriveAesKey',
      'deriveSubkey',
      'openVault',
      'readPrfOutput',
      'removeSlot',
      'replacePayload',
      'rootOf',
      'rootPayload',
      'slotIdFor',
    ].sort()
  );
  const main = await import('../src/index.js');
  const standalone = await import('../src/standalone/index.js');
  for (const name of ['createVaultKeeper', 'rootPayload', 'rootOf']) {
    expect(main[name]).toBe(vault[name]);
    expect(standalone[name]).toBe(vault[name]);
  }
});
