'use strict';
// Read-only launch metadata. Never executes/resolves a package through require.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const PROJECT = '/work/project';
const FIXED = [
  '/usr/local/bin/node', '/bin/sh', '/lane-bin/yarn',
  PROJECT + '/.yarn/releases/yarn-3.2.1.cjs',
  PROJECT + '/packages/host-lite/node_modules/.bin/vite',
  PROJECT + '/node_modules/.bin/vite',
  PROJECT + '/packages/host-lite/node_modules/vite/bin/vite.js',
  PROJECT + '/node_modules/vite/bin/vite.js',
];
const TEMP_NAME = /^xfs-[A-Za-z0-9]{6,64}$/;
const LIMITS = { mountBytes: 262144, mountLines: 2048, tmpEntries: 128,
  temporaryDirectories: 8, shimObservations: 16, watcherEvents: 128, outputBytes: 65536 };

function safeError(error) {
  return ['ENOENT', 'EACCES', 'EPERM', 'ENOTDIR', 'ELOOP', 'ENOSPC'].includes(error && error.code)
    ? error.code : 'OTHER';
}
function reviewedPath(value) {
  return typeof value === 'string' && path.posix.normalize(value) === value && (
    value === '/' || value === '/work' || value === PROJECT || value.startsWith(PROJECT + '/') ||
    value === '/tmp' || /^\/tmp\/xfs-[A-Za-z0-9]{6,64}(?:\/vite)?$/.test(value) ||
    ['/usr', '/usr/local', '/usr/local/bin', '/usr/local/bin/node', '/usr/bin', '/usr/bin/sh',
      '/usr/bin/dash', '/bin', '/bin/sh', '/lane-bin', '/lane-bin/yarn'].includes(value));
}
function statFacts(stat) {
  return { mode: (Number(stat.mode) & 0o7777).toString(8), uid: String(stat.uid), gid: String(stat.gid),
    device: String(stat.dev), inode: String(stat.ino), size: String(stat.size),
    type: stat.isSymbolicLink() ? 'symlink' : stat.isDirectory() ? 'directory' : stat.isFile() ? 'regular' : 'other' };
}
function metadata(filename) {
  if (!reviewedPath(filename)) throw new Error('Unreviewed metadata path');
  const value = { path: filename };
  try {
    value.lstat = statFacts(fs.lstatSync(filename, { bigint: true }));
    const resolved = fs.realpathSync(filename);
    if (reviewedPath(resolved)) {
      value.realpath = resolved;
      value.resolvedStat = statFacts(fs.statSync(resolved, { bigint: true }));
    } else value.realpathOutsideReviewedPaths = true;
  } catch (error) { value.error = safeError(error); }
  return value;
}
function ancestors(filename) {
  const values = [];
  for (let current = path.posix.dirname(filename); ; current = path.posix.dirname(current)) {
    if (!reviewedPath(current)) throw new Error('Unreviewed ancestor');
    values.push(metadata(current));
    if (current === '/') return values.reverse();
    if (values.length > 16) throw new Error('Ancestor bound');
  }
}
function unescapeMount(value) {
  return value.replace(/\\(040|011|012|134)/g, (_, digits) => String.fromCharCode(parseInt(digits, 8)));
}
function optionList(text) {
  const simple = new Set(['ro', 'rw', 'exec', 'noexec', 'nosuid', 'suid', 'nodev', 'dev',
    'relatime', 'noatime', 'strictatime', 'nodiratime', 'lazytime']);
  return text.split(',').filter(x => simple.has(x) || /^(size|mode|uid|gid|nr_inodes)=[0-9a-fA-FkmgtKMGT]+$/.test(x));
}
function coveringMounts(text, targets) {
  if (Buffer.byteLength(text) > LIMITS.mountBytes) throw new Error('Mount input bound');
  const lines = text.trim().split('\n');
  if (lines.length > LIMITS.mountLines) throw new Error('Mount line bound');
  const parsed = [];
  for (const line of lines) {
    const parts = line.split(' '), divider = parts.indexOf('-');
    if (divider < 6 || parts.length < divider + 4 || !/^\d+$/.test(parts[0]) || !/^\d+$/.test(parts[1]))
      throw new Error('Malformed mountinfo');
    const point = unescapeMount(parts[4]);
    if (!reviewedPath(point)) continue;
    if (!/^[A-Za-z0-9_.+-]{1,32}$/.test(parts[divider + 1])) throw new Error('Filesystem label bound');
    parsed.push({ mountId: parts[0], parentId: parts[1], mountPoint: point,
      filesystemType: parts[divider + 1], mountOptions: optionList(parts[5]),
      superOptions: optionList(parts[divider + 3]) });
  }
  return targets.map(target => {
    if (!reviewedPath(target)) throw new Error('Unreviewed mount target');
    const covering = parsed.filter(row => row.mountPoint === '/' || target === row.mountPoint || target.startsWith(row.mountPoint + '/'))
      .sort((a, b) => b.mountPoint.length - a.mountPoint.length)[0];
    return { target, coveringMount: covering || null };
  });
}
function snapshot(label, targets) {
  const value = { label, paths: targets.map(filename => ({ ...metadata(filename), ancestors: ancestors(filename) })) };
  try {
    const fd = fs.openSync('/proc/self/mountinfo', 'r');
    let text;
    try {
      const bytes = Buffer.alloc(LIMITS.mountBytes + 1);
      let count = 0, read;
      while (count < bytes.length && (read = fs.readSync(fd, bytes, count, bytes.length - count, null)) > 0) count += read;
      if (count > LIMITS.mountBytes) throw new Error('Mount input bound');
      text = bytes.subarray(0, count).toString('utf8');
    } finally { fs.closeSync(fd); }
    value.mountinfoSha256 = crypto.createHash('sha256').update(text).digest('hex');
    value.mounts = coveringMounts(text, targets.concat(['/tmp']));
  } catch (error) { value.mountError = safeError(error); }
  return value;
}

function begin(emit) {
  const report = { schemaVersion: 1, mode: 'read-only-original-yarn-build-launch',
    commandUnchanged: true, environmentModified: false, permissionsModified: false,
    observedTemporaryShims: [], observationErrors: [], limits: LIMITS,
    shimObservationLimit: 'Filesystem events are best effort. Absence is not proof that no shim existed.' };
  const watches = [], directories = new Set(), signatures = new Set();
  let finished = false, observationStopped = false, eventCount = 0;
  const error = value => { if (report.observationErrors.length < 8) report.observationErrors.push(safeError(value)); };
  const eventAllowed = () => {
    if (finished || observationStopped) return false;
    if (++eventCount <= LIMITS.watcherEvents) return true;
    observationStopped = true;
    for (const watcher of watches) { try { watcher.close(); } catch (caught) { error(caught); } }
    return false;
  };
  const inspectShim = directory => {
    if (finished || report.observedTemporaryShims.length >= LIMITS.shimObservations) return;
    try {
      const filename = '/tmp/' + directory + '/vite';
      const observed = snapshot('observed-yarn-temporary-vite-shim', [filename]);
      if (observed.paths[0].error === 'ENOENT') return;
      const signature = JSON.stringify(observed.paths);
      if (!signatures.has(signature)) { signatures.add(signature); report.observedTemporaryShims.push(observed); }
    } catch (caught) { error(caught); }
  };
  const watchDirectory = name => {
    if (!TEMP_NAME.test(name) || directories.has(name) || directories.size >= LIMITS.temporaryDirectories) return;
    directories.add(name);
    try {
      const directory = '/tmp/' + name;
      const facts = fs.lstatSync(directory);
      if (!facts.isDirectory() || facts.isSymbolicLink() || fs.realpathSync(directory) !== directory) return;
      const watcher = fs.watch(directory, { persistent: false }, (_event, file) => {
        if (!eventAllowed()) return;
        if (file === null || String(file) === 'vite') inspectShim(name);
      });
      watcher.on('error', error); watches.push(watcher);
      inspectShim(name);
    } catch (caught) { error(caught); }
  };
  try {
    report.before = snapshot('before-original-yarn-spawn', FIXED);
    const directory = fs.opendirSync('/tmp');
    try {
      let entry, count = 0;
      while ((entry = directory.readSync()) !== null) {
        if (++count > LIMITS.tmpEntries) { report.temporaryEntryBoundExceeded = true; break; }
        watchDirectory(entry.name);
      }
    } finally { directory.closeSync(); }
    const watcher = fs.watch('/tmp', { persistent: false }, (_event, file) => {
      if (!eventAllowed() || file === null) return;
      watchDirectory(String(file));
    });
    watcher.on('error', error); watches.push(watcher);
  } catch (caught) { error(caught); }
  return {
    finish(code, signal) {
      if (finished) return;
      for (const name of directories) inspectShim(name);
      finished = true;
      for (const watcher of watches) { try { watcher.close(); } catch (caught) { error(caught); } }
      try { report.after = snapshot('after-original-yarn-exit', FIXED); } catch (caught) { error(caught); }
      report.originalYarnExit = { code, signal };
      report.observedEventCount = Math.min(eventCount, LIMITS.watcherEvents + 1);
      const text = JSON.stringify(report);
      if (Buffer.byteLength(text) <= LIMITS.outputBytes) emit(text);
      else emit(JSON.stringify({ schemaVersion: 1, mode: report.mode, diagnosticBoundExceeded: true,
        originalYarnExit: report.originalYarnExit, observationErrors: report.observationErrors }));
    },
  };
}
module.exports = { begin, coveringMounts, optionList, reviewedPath };
