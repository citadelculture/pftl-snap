'use strict';
// This file is the only JavaScript workload. Builtins only; no repository code.
const fs = require('node:fs');
const os = require('node:os');
const net = require('node:net');
const dgram = require('node:dgram');
const readline = require('node:readline');
const crypto = require('node:crypto');

function emit(value) { process.stdout.write(JSON.stringify(value) + '\n'); }
const nonce = process.argv[2];
if (!/^[a-f0-9]{32}$/.test(nonce || '')) process.exit(2);
const user = os.userInfo();
const status = fs.readFileSync('/proc/self/status', 'utf8');
const field = name => (status.match(new RegExp('^' + name + ':\\s*(.+)$', 'm')) || [])[1];
const control = Object.fromEntries(Object.entries(process.env).filter(([key]) =>
  key === 'CODEX_SANDBOX' || key.startsWith('CODEX_SANDBOX_')).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0));
const controlHash = crypto.createHash('sha256').update(JSON.stringify(control)).digest('hex');
const permitted = new Set(['HOME', 'PATH', 'LANG', 'CI', 'NODE_VERSION', 'YARN_VERSION', 'HOSTNAME']);
const unexpectedEnvironment = Object.keys(process.env).filter(key => !permitted.has(key) &&
  key !== 'CODEX_SANDBOX' && !key.startsWith('CODEX_SANDBOX_'));
let dockerSocketStat = 'absent';
try { fs.statSync('/var/run/docker.sock'); dockerSocketStat = 'present'; } catch (error) {
  if (error.code === 'EACCES') dockerSocketStat = 'denied';
  else if (error.code !== 'ENOENT') throw error;
}
fs.writeFileSync('/home/node/boundary-canary', 'SYNTHETIC-NONSECRET');
emit({ event: 'ready', nonce, uid: process.getuid(), gid: process.getgid(),
  accountUid: user.uid, accountGid: user.gid, accountHome: user.homedir,
  homeMatchesRealAccount: process.env.HOME === user.homedir && user.homedir === '/home/node',
  canaryRoundTrip: fs.readFileSync('/home/node/boundary-canary', 'utf8') === 'SYNTHETIC-NONSECRET',
  capInh: field('CapInh'), capPrm: field('CapPrm'), capEff: field('CapEff'),
  capBnd: field('CapBnd'), capAmb: field('CapAmb'), noNewPrivs: field('NoNewPrivs'), seccomp: field('Seccomp'),
  controlsSha256: controlHash, unexpectedEnvironmentCount: unexpectedEnvironment.length,
  dockerSocketStat, nodeVersion: process.versions.node, platform: process.platform,
  arch: process.arch });

async function one(command) {
  if (Object.keys(command).sort().join(',') !== 'address,id,operation,port' ||
      !/^[a-z0-9_]+$/.test(command.id) || !['tcp', 'udp'].includes(command.operation) ||
      !net.isIP(command.address) || !Number.isInteger(command.port) ||
      command.port < 1 || command.port > 65535) throw new Error('Invalid exact probe command');
  const result = { event: 'result', ...command };
  await new Promise(resolve => {
    let finished = false;
    const socket = command.operation === 'tcp' ? new net.Socket() :
      dgram.createSocket(net.isIP(command.address) === 6 ? 'udp6' : 'udp4');
    const finish = (outcome, errorCode) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      if (command.operation === 'tcp') socket.destroy();
      else { try { socket.close(); } catch {} }
      result.outcome = outcome;
      if (errorCode) result.errorCode = String(errorCode).slice(0, 48);
      resolve();
    };
    const timer = setTimeout(() => finish('timeout'), 1800);
    socket.once('error', error => finish('error', error.code || 'ERROR'));
    if (command.operation === 'tcp') {
      socket.once('connect', () => finish('connected'));
      socket.connect({ host: command.address, port: command.port, family: net.isIP(command.address) });
    } else {
      // A valid benign query for a reserved .invalid name; no response/content read.
      const payload = Buffer.from('12340100000100000000000008626f756e6461727907696e76616c69640000010001', 'hex');
      socket.send(payload, command.port, command.address, error => {
        if (error) return finish('error', error.code || 'ERROR');
        setTimeout(() => finish('sent'), 180);
      });
    }
  });
  emit(result);
}

// No network operation starts until the trusted host installs/readbacks the filter
// and sends an exact first command on stdin. One operation is outstanding at a time.
const lines = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
(async () => {
  let count = 0;
  for await (const line of lines) {
    if (line.length > 512 || ++count > 13) throw new Error('Probe bound exceeded');
    await one(JSON.parse(line));
  }
  emit({ event: 'complete', operations: count });
})().catch(() => { emit({ event: 'failure', reason: 'builtin-probe-failure' }); process.exitCode = 1; });
