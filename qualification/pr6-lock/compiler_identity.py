"""Strict data-only binding of the actual workspace compiler's two invocations."""
import json
from pathlib import PurePosixPath
import re

PREFIX = 'PFTL_LOCKED_COMPILER_IDENTITY '


def identity_from_output(text, *, version_phase=False):
    rows = [line[len(PREFIX):] for line in text.splitlines() if line.startswith(PREFIX)]
    if len(rows) != 1 or len(rows[0]) > 16384:
        raise ValueError('Exactly one bounded compiler identity required')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('Duplicate identity key')
            result[key] = value
        return result
    value = json.loads(rows[0], object_pairs_hook=unique)
    if (set(value) != {'schemaVersion', 'packageName', 'version', 'workspace', 'nodeVersion', 'files'}
            or type(value['schemaVersion']) is not int or value['schemaVersion'] != 1
            or value['packageName'] != 'typescript' or value['version'] != '5.0.4'
            or value['workspace'] != 'packages/host-lite' or value['nodeVersion'] != 'v24.21.0'
            or not isinstance(value['files'], dict)
            or set(value['files']) != {'packageJson', 'cli', 'implementation', 'library'}):
        raise ValueError('Unexpected workspace compiler identity')
    paths = {}
    for name, row in value['files'].items():
        if not isinstance(row, dict) or set(row) != {'path', 'sha256'}:
            raise ValueError('Invalid compiler file binding')
        if not isinstance(row['path'], str) or not isinstance(row['sha256'], str):
            raise ValueError('Invalid compiler file types')
        path = PurePosixPath(row['path'])
        if path.is_absolute() or '..' in path.parts or '\\' in row['path'] or not re.fullmatch(r'[0-9a-f]{64}', row['sha256']):
            raise ValueError('Compiler path/hash escaped binding')
        paths[name] = path
    root = paths['packageJson'].parent
    if root.parts[-2:] != ('node_modules', 'typescript') or paths != {
            'packageJson': root / 'package.json', 'cli': root / 'bin/tsc',
            'implementation': root / 'lib/tsc.js', 'library': root / 'lib/typescript.js'}:
        raise ValueError('Compiler entry/implementation roots disagree')
    if version_phase and text.splitlines().count('Version 5.0.4') != 1:
        raise ValueError('Actual TypeScript version invocation missing')
    return value


def compare_compiler(identity, typecheck):
    if identity != typecheck:
        raise ValueError('Actual compiler paths or bytes changed between phases')
    return {'actualCompilerBindingMatched': True, 'identity': identity}
