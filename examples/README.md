# Examples

Three demo apps, one per way of using the package, and one pnpm workspace
for all of them.

| Demo | Option | What signs an entry |
| --- | --- | --- |
| `webauthn-todo-demo` | default | a key derived from the passkey, in the OrbitDB keystore |
| `ed25519-encrypted-keystore-demo` | keystore DID + `encryptKeystore` | an Ed25519 key sealed by the passkey, in memory for the session |
| `webauthn-varsig-demo` | varsig | the passkey itself, every write |

## Running one

Install once, here — the demos declare no dependencies of their own, they all
come from `package.json` in this directory, and the library is linked from
the repository root:

```sh
pnpm install --frozen-lockfile        # in the repository root, for the library
pnpm --dir examples install --frozen-lockfile
pnpm --dir examples/webauthn-todo-demo run dev
```

`pnpm --dir examples -r run build` builds all three; that is what CI and the
Pages deploy run.

## Layout

- `shared/` — the page frame, brand and the code every demo needs the same
  way. Files here resolve packages by walking up to `examples/node_modules`,
  which is why the demos must not carry their own.
- `<demo>/` — a SvelteKit app: `src/lib/WebAuthnTodo.svelte` is the demo,
  the rest is scaffolding.
