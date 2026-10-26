'use strict';
// Runs only inside the admitted container, through Yarn workspace exec.
// Resolves files as data; invokes exactly the bound CLI without importing it here.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const cp = require('node:child_process');
const { createRequire } = require('node:module');
const assert = require('node:assert/strict');
const phase = process.argv[2];
assert(['compiler-identity', 'typecheck'].includes(phase));
assert.equal(process.version, 'v24.21.0');
assert.equal(process.cwd(), '/work/project/packages/host-lite');
const project = '/work/project/';
function protectedFile(file) {
  const real = fs.realpathSync(file);
  assert(real.startsWith(project));
  const st = fs.statSync(real);
  assert(st.isFile());
  return { path: real.slice(project.length), sha256: crypto.createHash('sha256').update(fs.readFileSync(real)).digest('hex') };
}
function directCompilerPath(pkg, packageRoot) {
  if (!pkg || pkg.name !== 'typescript' || pkg.version !== '5.0.4'
      || !pkg.bin || typeof pkg.bin !== 'object' || Array.isArray(pkg.bin)
      || pkg.bin.tsc !== './bin/tsc'
      || typeof packageRoot !== 'string' || !packageRoot.startsWith('/work/project/')
      || !packageRoot.endsWith('/node_modules/typescript')
      || packageRoot.includes('\\') || packageRoot.split('/').some(p => p === '.' || p === '..')
      || packageRoot.includes('//')) {
    throw new Error('Exact workspace TypeScript package/bin mapping required');
  }
  return packageRoot + '/bin/tsc';
}
function binding() {
  const req = createRequire('/work/project/packages/host-lite/package.json');
  const packageFile = fs.realpathSync(req.resolve('typescript/package.json'));
  const pkg = JSON.parse(fs.readFileSync(packageFile, 'utf8'));
  assert.equal(pkg.name, 'typescript');
  assert.equal(pkg.version, '5.0.4');
  const packageRoot = path.dirname(packageFile);
  // Yarn3.2.1 prepends temporary real shell shims to PATH. They are not the
  // package CLI and are deliberately neither selected nor executed here.
  const designatedCli = directCompilerPath(pkg, packageRoot);
  const cli = fs.realpathSync(designatedCli);
  assert.equal(cli, designatedCli);
  return { schemaVersion: 1, packageName: pkg.name, version: pkg.version,
    workspace: 'packages/host-lite', nodeVersion: process.version,
    files: { packageJson: protectedFile(packageFile), cli: protectedFile(cli),
      implementation: protectedFile(path.join(packageRoot, 'lib/tsc.js')),
      library: protectedFile(path.join(packageRoot, 'lib/typescript.js')) } };
}
const before = binding();
const args = phase === 'compiler-identity' ? ['--version'] : ['--noEmit', '--project', 'tsconfig.json'];
const result = cp.spawnSync('/usr/local/bin/node', [project + before.files.cli.path, ...args], {
  cwd: process.cwd(), env: process.env, stdio: phase === 'compiler-identity' ? ['ignore', 'pipe', 'inherit'] : 'inherit',
  encoding: 'utf8', timeout: phase === 'compiler-identity' ? 25000 : 295000,
});
assert.ifError(result.error);
assert.equal(result.signal, null);
assert.equal(result.status, 0);
if (phase === 'compiler-identity') {
  assert.equal(result.stdout.trim(), 'Version 5.0.4');
  process.stdout.write(result.stdout);
}
const after = binding();
assert.deepEqual(after, before);
console.log('PFTL_LOCKED_COMPILER_IDENTITY ' + JSON.stringify(before));
