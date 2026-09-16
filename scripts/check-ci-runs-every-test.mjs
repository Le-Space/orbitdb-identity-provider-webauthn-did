/**
 * Fails when CI does not run every test file in tests/.
 *
 * ci.yml names the suites it runs, step by step, because they need different
 * demo servers and environments. A new file therefore runs in CI only if
 * someone also adds it there — and nothing noticed when that did not happen:
 * eight suites written between July and September 2026 never ran in CI, while
 * release.yml publishes with --ignore-scripts because CI is its test gate.
 *
 * A file counts as run when a `run:` command in ci.yml names it, directly or
 * through package.json scripts, or when such a command runs a Playwright
 * config without naming files and Playwright lists the file for that config.
 *
 *   node scripts/check-ci-runs-every-test.mjs
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const read = (path) => readFileSync(join(root, path), 'utf8');
const { scripts } = JSON.parse(read('package.json'));

/** The value of every `run:` key in a workflow, block scalars included. */
function runValues(workflow) {
  const lines = workflow.split('\n');
  const values = [];
  for (let i = 0; i < lines.length; i++) {
    const key = lines[i].match(/^\s*(?:- )?run:\s*(.*)$/);
    if (!key) continue;
    const [, value] = key;
    if (!/^[|>]/.test(value)) {
      values.push(value);
      continue;
    }
    // A block ends at the first line not indented past the `run` key itself —
    // in `- run: |` that key sits two columns right of the dash, level with
    // the step's other keys.
    const column = lines[i].indexOf('run:');
    const block = [];
    while (
      i + 1 < lines.length &&
      (!lines[i + 1].trim() || lines[i + 1].search(/\S/) > column)
    ) {
      block.push(lines[++i]);
    }
    values.push(block.join('\n'));
  }
  return values;
}

/** A command, followed by the body of every package.json script it runs. */
function expand(command, seen = new Set()) {
  let text = command;
  for (const [, name] of command.matchAll(/\b(?:npm|pnpm) run ([\w:.-]+)/g)) {
    if (name in scripts && !seen.has(name)) {
      seen.add(name);
      text += '\n' + expand(scripts[name], seen);
    }
  }
  return text;
}

const listings = new Map();

/** The test files Playwright selects for a config, relative to the repository. */
function listed(config) {
  if (!listings.has(config)) {
    const dir = mkdtempSync(join(tmpdir(), 'ci-test-files-'));
    const output = join(dir, 'list.json');
    let selected;
    try {
      execFileSync(
        'pnpm',
        [
          'exec',
          'playwright',
          'test',
          `--config=${config}`,
          '--list',
          '--reporter=json',
        ],
        {
          cwd: root,
          env: { ...process.env, PLAYWRIGHT_JSON_OUTPUT_FILE: output },
          stdio: ['ignore', 'ignore', 'inherit'],
        }
      );
      const { config: resolved, suites } = JSON.parse(
        readFileSync(output, 'utf8')
      );
      selected = suites.map((suite) =>
        relative(root, join(resolved.rootDir, suite.file))
      );
    } catch {
      // Playwright has already printed why, typically a suite that fails to
      // import. Such a suite cannot run in CI either.
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
    if (!selected) {
      console.error(
        `Playwright could not list the files ${config} selects; its error is above.`
      );
      process.exit(1);
    }
    listings.set(config, selected);
  }
  return listings.get(config);
}

/** The test files one `playwright test` command runs. */
function selectedBy(command) {
  const named = [...command.matchAll(/\btests\/[\w./-]+\.test\.js\b/g)].map(
    ([file]) => file
  );
  if (named.length) return named;
  const config = command.match(/(?:--config[= ]|-c )(\S+)/)?.[1];
  return listed(config ?? 'playwright.config.js');
}

const run = new Set(
  runValues(read('.github/workflows/ci.yml'))
    .map((value) => expand(value))
    .flatMap((text) => text.split(/\n|&&|\|\||;/))
    .filter((command) => !command.trimStart().startsWith('#'))
    .filter((command) => /\bplaywright test\b/.test(command))
    .flatMap(selectedBy)
);

const files = readdirSync(join(root, 'tests'))
  .filter((name) => name.endsWith('.test.js'))
  .map((name) => `tests/${name}`);
const missing = files.filter((file) => !run.has(file));

if (missing.length) {
  console.error(
    `CI does not run ${missing.length} of ${files.length} test files:`
  );
  for (const file of missing) console.error(`  ${file}`);
  console.error(
    'Add a step for it to .github/workflows/ci.yml, or — if it opens no page — add it to playwright.node.config.js.'
  );
  process.exit(1);
}
console.log(`CI runs all ${files.length} test files in tests/.`);
