#!/usr/bin/env python3
"""Offline state backup/restore. Stop every journal/rollup writer first."""
import argparse
import fcntl
import os
import hashlib
import json
import pathlib
import shutil
import sqlite3
import subprocess
import tempfile


def digest(path):
    with path.open('rb') as stream:
        value = hashlib.sha256()
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            value.update(block)
        return value.hexdigest()


def checked_files(root):
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('symbolic links are not supported in state backups')
        if path.is_file():
            yield path
        elif not path.is_dir():
            raise ValueError('state backups contain only regular files and directories')


def backup(args, stage):
    (stage / 'journal').mkdir()
    (stage / 'rollups').mkdir()
    journal = args.journal / 'audit-journal.jsonl'
    if journal.is_symlink():
        raise ValueError('journal must be a regular file')
    with journal.open('rb') as journal_stream:
        fcntl.flock(journal_stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with (stage / 'journal' / journal.name).open('wb') as output:
            shutil.copyfileobj(journal_stream, output)
        list(checked_files(args.checkpoints))
        shutil.copytree(args.checkpoints, stage / 'checkpoints', symlinks=False)
        with sqlite3.connect(args.rollups.resolve().as_uri() + '?mode=ro', uri=True) as source:
            with sqlite3.connect(stage / 'rollups' / 'usage.sqlite') as destination:
                source.backup(destination)
                if destination.execute('PRAGMA integrity_check').fetchone() != ('ok',):
                    raise ValueError('rollup integrity check failed')
        manifest = {'version': 1, 'files': {str(path.relative_to(stage)): digest(path) for path in checked_files(stage)}}
        (stage / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')


def restore(args, stage):
    manifest = json.loads((args.source / 'manifest.json').read_text())
    if manifest.get('version') != 1 or not isinstance(manifest.get('files'), dict):
        raise ValueError('unsupported backup manifest')
    files = {str(path.relative_to(args.source)): path for path in checked_files(args.source) if path.name != 'manifest.json'}
    if not {'journal/audit-journal.jsonl', 'rollups/usage.sqlite'} <= set(files):
        raise ValueError('backup is missing mandatory state files')
    if set(files) != set(manifest['files']):
        raise ValueError('backup file set differs from manifest')
    for name, path in files.items():
        if digest(path) != manifest['files'][name]:
            raise ValueError('backup checksum mismatch')
        output = stage / name
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, output)
    (stage / 'checkpoints').mkdir(exist_ok=True)
    with sqlite3.connect(stage / 'rollups' / 'usage.sqlite') as connection:
        if connection.execute('PRAGMA integrity_check').fetchone() != ('ok',):
            raise ValueError('restored rollup integrity check failed')
    command = [str(args.binary), 'audit', 'verify', str(stage / 'journal'), '--checkpoints', str(stage / 'checkpoints'), '--json']
    for key in args.public_key:
        command.extend(['--public-key', key])
    subprocess.run(command, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    save = commands.add_parser('backup')
    save.add_argument('--journal', type=pathlib.Path, required=True)
    save.add_argument('--checkpoints', type=pathlib.Path, required=True)
    save.add_argument('--rollups', type=pathlib.Path, required=True)
    load = commands.add_parser('restore')
    load.add_argument('--source', type=pathlib.Path, required=True)
    load.add_argument('--binary', type=pathlib.Path, required=True)
    load.add_argument('--public-key', action='append', required=True)
    for command in (save, load):
        command.add_argument('--destination', type=pathlib.Path, required=True)
        command.add_argument('--quiesced', action='store_true', required=True, help='all writers are stopped')
    args = parser.parse_args()
    if args.destination.exists():
        parser.error('destination must not exist; restore into a new directory')
    args.destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.mcp-state-', dir=args.destination.parent) as temporary:
        stage = pathlib.Path(temporary) / 'state'
        stage.mkdir(mode=0o700)
        (backup if args.command == 'backup' else restore)(args, stage)
        for path in checked_files(stage):
            with path.open('rb') as stream:
                os.fsync(stream.fileno())
        for path in [*stage.rglob('*'), stage]:
            if path.is_dir():
                descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        stage.rename(args.destination)
        descriptor = os.open(args.destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    print(json.dumps({'status': 'ok', 'destination': str(args.destination)}))


if __name__ == '__main__':
    main()
