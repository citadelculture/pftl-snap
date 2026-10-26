"""Bounded data-only source and output checks; never load a build artifact."""
import hashlib
from html.parser import HTMLParser
import os
from pathlib import Path, PurePosixPath
import stat
from urllib.parse import unquote, urlsplit

DIST = 'packages/host-lite/dist'
MAX_FILES = 256
MAX_FILE_BYTES = 8 * 1024**2
MAX_TOTAL_BYTES = 32 * 1024**2


def regular(root, path):
    if root.is_symlink():
        raise ValueError('Symlink root')
    for part in path.relative_to(root).parts:
        root = root / part
        if root.is_symlink():
            raise ValueError('Symlink source/output')
    if not path.is_file():
        raise ValueError('Regular file required')


def check_frozen_source(project, inventory, allow_dist=False):
    project = Path(project)
    if project.is_symlink():
        raise ValueError('Symlink project')
    expected = {}
    for row in inventory:
        name = PurePosixPath(row['path'])
        if name.is_absolute() or '..' in name.parts or '\\' in row['path'] or row['path'] in expected:
            raise ValueError('Unsafe/duplicate source inventory')
        expected[row['path']] = row
        path = project / name
        regular(project, path)
        if (path.stat().st_size != row['bytes'] or oct(stat.S_IMODE(path.stat().st_mode)) != row['mode']
                or hashlib.sha256(path.read_bytes()).hexdigest() != row['sha256']):
            raise ValueError('Frozen source or lock drift: ' + row['path'])
    for parent, dirs, names in os.walk(project, followlinks=False):
        parent = Path(parent)
        keep = []
        for name in dirs:
            path = parent / name
            relative = path.relative_to(project).as_posix()
            if path.is_symlink():
                raise ValueError('Unexpected source/output directory symlink')
            if name == 'node_modules' or relative in {'.yarn/cache', '.yarn/unplugged'}:
                continue
            if relative == DIST:
                if not allow_dist:
                    raise ValueError('Build output exists before build')
                inspect_dist(project)
                continue
            keep.append(name)
        dirs[:] = keep
        for name in names:
            path = parent / name
            relative = path.relative_to(project).as_posix()
            if path.is_symlink() or not path.is_file():
                raise ValueError('Unexpected nonregular source')
            if relative not in expected and relative != '.yarn/install-state.gz':
                raise ValueError('Unexpected source file: ' + relative)
    return {'sourceFiles': len(expected), 'allFrozenSourceAndLockBytesPreserved': True, 'distPermitted': allow_dist}


class References(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.refs = []
        self.modules = []

    def handle_starttag(self, tag, attrs):
        # Duplicate attributes are ambiguous and must not be silently collapsed.
        keys = [key for key, _ in attrs]
        if len(set(keys)) != len(keys):
            raise ValueError('Duplicate HTML attributes')
        attrs = dict(attrs)
        if tag == 'script' and attrs.get('src') is not None:
            self.refs.append(attrs['src'])
            if attrs.get('type') == 'module':
                self.modules.append(attrs['src'])
        if tag == 'link' and attrs.get('href') is not None:
            self.refs.append(attrs['href'])


def asset_name(raw):
    if not isinstance(raw, str) or not raw or raw != raw.strip() or '\\' in raw:
        raise ValueError('Invalid build reference')
    url = urlsplit(raw)
    if url.scheme or url.netloc or raw.startswith('//'):
        raise ValueError('Remote build reference')
    decoded = unquote(url.path, errors='strict')
    if '%' in decoded or '\\' in decoded or '\x00' in decoded or decoded.startswith('//'):
        raise ValueError('Ambiguous encoded build reference')
    path = PurePosixPath(decoded.lstrip('/'))
    if not path.parts or '..' in path.parts or decoded.endswith('/'):
        raise ValueError('Unsafe asset traversal')
    return path.as_posix()


def inspect_dist(project):
    project = Path(project)
    directory = project / DIST
    for part in Path(DIST).parts:
        project = project / part
        if project.is_symlink():
            raise ValueError('Symlink dist ancestry')
    if not directory.is_dir():
        raise ValueError('Missing dist directory')
    files = []
    total = 0
    for parent, dirs, names in os.walk(directory, followlinks=False):
        for name in dirs:
            if (Path(parent) / name).is_symlink():
                raise ValueError('Symlink dist directory')
        for name in names:
            path = Path(parent) / name
            regular(directory, path)
            size = path.stat().st_size
            if not 0 < size <= MAX_FILE_BYTES:
                raise ValueError('Empty or oversized build artifact')
            total += size
            if len(files) >= MAX_FILES or total > MAX_TOTAL_BYTES:
                raise ValueError('Build artifact count/total bound exceeded')
            files.append({'path': path.relative_to(directory).as_posix(), 'bytes': size,
                          'sha256': hashlib.sha256(path.read_bytes()).hexdigest()})
    by_name = {row['path']: row for row in files}
    if 'index.html' not in by_name:
        raise ValueError('Missing index.html')
    parser = References()
    parser.feed((directory / 'index.html').read_text(encoding='utf-8', errors='strict'))
    parser.close()
    if not parser.modules:
        raise ValueError('No actual module script in build output')
    refs = [asset_name(raw) for raw in parser.refs]
    if any(name not in by_name for name in refs):
        raise ValueError('Referenced build asset missing')
    return {'files': sorted(files, key=lambda row: row['path']), 'fileCount': len(files),
            'totalBytes': total, 'referencedAssets': sorted(set(refs)),
            'moduleScripts': [asset_name(raw) for raw in parser.modules], 'artifactCodeExecuted': False}
