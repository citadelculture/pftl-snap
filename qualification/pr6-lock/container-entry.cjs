'use strict';
// A boundary wrapper, not a replacement for Yarn or the original plugin/hook.
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');
const cp = require('node:child_process');
const assert = require('node:assert/strict');
const phase = process.argv[2];
assert(['immutable', 'compiler-identity', 'typecheck', 'production-build'].includes(phase));
const user = os.userInfo();
assert.equal(user.username, 'node');
assert.equal(user.uid, 1000);
assert.equal(user.homedir, '/home/node');
assert.equal(process.env.HOME, user.homedir);
assert.equal(process.version, 'v24.21.0');
assert.equal(process.platform, 'linux');
assert.equal(process.arch, 'x64');
assert(!fs.existsSync('/var/run/docker.sock'));
assert(!fs.existsSync('/github'));
assert(!fs.existsSync('/home/runner'));
assert(!Object.keys(process.env).some(k => /^(ACTIONS_|GITHUB_|INPUT_|RUNNER_)/.test(k)));
assert(!Object.keys(process.env).some(k => /^(http|https|all|no)_proxy$/i.test(k)));
const controls = Object.fromEntries(Object.entries(process.env).filter(([k]) => k === 'CODEX_SANDBOX' || k.startsWith('CODEX_SANDBOX_')));
const childEnv = { HOME: process.env.HOME, PATH: '/lane-bin:/usr/local/bin:/usr/bin:/bin', LANG: 'C.UTF-8', CI: 'true', ...controls };
const status = fs.readFileSync('/proc/self/status', 'utf8');
for (const name of ['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'])
  assert.equal(status.match(new RegExp(`^${name}:\\s*([0-9a-f]+)$`, 'm'))?.[1], '0000000000000000');
assert.equal(status.match(/^NoNewPrivs:\s*(\d+)$/m)?.[1], '1');
assert.equal(status.match(/^Seccomp:\s*(\d+)$/m)?.[1], '2');
assert.equal(fs.readFileSync('/etc/resolv.conf', 'utf8'), '');
const yarn = '/work/project/.yarn/releases/yarn-3.2.1.cjs';
assert.equal(crypto.createHash('sha256').update(fs.readFileSync(yarn)).digest('hex'), 'f1c9f039ab3b236c7abb7bafa0a0f266aa6bc5a3dbe7c684b561f03c0005d043');
assert.equal(fs.realpathSync('/lane-bin/yarn'), yarn);
assert.equal(fs.realpathSync('/lane-bin/node'), '/usr/local/bin/node');
assert.equal(cp.execFileSync('/lane-bin/yarn', ['--version'], { cwd: '/work/project', env: childEnv, encoding: 'utf8', timeout: 30000 }).trim(), '3.2.1');
{
  const commands = {
    immutable: ['install', '--immutable'],
    'compiler-identity': ['workspace', '@postfiat/pftl-host-lite', 'exec', 'node', '/lane/locked-compiler.cjs', 'compiler-identity'],
    typecheck: ['workspace', '@postfiat/pftl-host-lite', 'exec', 'node', '/lane/locked-compiler.cjs', 'typecheck'],
    'production-build': ['workspace', '@postfiat/pftl-host-lite', 'build'],
  };
  const args = [yarn, ...commands[phase]];
  const child = cp.spawn('/usr/local/bin/node', args, { cwd: '/work/project', env: childEnv, stdio: 'inherit' });
  for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => child.kill(signal));
  child.on('error', () => { process.exitCode = 1; });
  child.on('exit', (code, signal) => { process.exitCode = signal ? 1 : (code ?? 1); });
}
