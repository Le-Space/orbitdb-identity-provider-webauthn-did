# Examples

Three demo apps, one per way of using the package, and one pnpm workspace
for all of them.

| Demo | Option | What signs an entry |
| --- | --- | --- |
| `webauthn-todo-demo` | default | a key derived from the passkey, in the OrbitDB keystore |
| `ed25519-encrypted-keystore-demo` | keystore DID + `encryptKeystore`, or a worker signer | an Ed25519 key sealed by the passkey and unlocked into memory for the session — or one that never leaves a Web Worker |
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

- `shared/lib/options/` — one module per option, each building the
  identity for it: `default-path.js`, `encrypted-keystore.js`, `varsig.js`.
  This is the code to read for "how do I use this option".
- `shared/lib/stack.js` — libp2p, Helia, OrbitDB, cleanup and reset, the
  same for all three. Each demo passes a namespace so their IndexedDB stores
  stay apart on the one origin the demos are published under.
- `shared/lib/` also holds the verifier (`verification.js`), the forgery
  checks and the prompt counter that back the panels, and `database.js`,
  the todo store.
- `shared/` otherwise — the page frame, brand and the switcher. Files here
  resolve packages by walking up to `examples/node_modules`, which is why the
  demos must not carry their own.
- `<demo>/` — a SvelteKit app: `src/lib/WebAuthnTodo.svelte` is the demo,
  `src/lib/orbitdb.js` wires the option module into the stack, the rest is
  scaffolding.
