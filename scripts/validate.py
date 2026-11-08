#!/usr/bin/env python3
"""Fail CI if the 30 x 3 archive or the per-scanner totals are inconsistent."""
from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path


def validate(root: Path, manifest_path: Path):
    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))['projects']
    assert len(manifest) == 30, 'Expected exactly 30 projects'
    names = {p['name'] for p in manifest}
    assert len(names) == 30, 'Duplicate project folder names'
    got = {x.name for x in root.iterdir() if x.is_dir()}
    assert names == got, f'Unexpected or missing project folders: {names ^ got}'
    summary_path = root/'INDEX.csv'
    with summary_path.open(newline='', encoding='utf-8-sig') as file:
        index = list(csv.DictReader(file))
    assert len(index) == 30, f'Expected 30 index rows; got {len(index)}'
    for project in manifest:
        folder = root/project['name']
        expected = {'osv.json', 'grype.json', 'default.json'}
        actual = {x.name for x in folder.iterdir()}
        assert actual == expected, (project['name'], actual ^ expected)
        doc = json.loads((folder/'default.json').read_text(encoding='utf-8'))
        assert doc['project_id'] == project['id']
        assert doc['pinned_commit'] == project['ref']
        c = doc['counts']
        refs = doc['vulnerabilities']
        assert len(refs) == c['total'], project['name']
        assert c['osv'] == c['both'] + c['only_osv']
        assert c['grype'] == c['both'] + c['only_grype']
        assert c['total'] == (c['both'] + c['only_osv'] + c['only_grype'] +
                              c.get('independently_verified_but_not_detected', 0))
        for scanner, key in (('osv', 'results'), ('grype', 'matches')):
            result = json.loads((folder / (scanner + '.json')).read_text(encoding='utf-8'))
            assert isinstance(result, dict), (project['name'], scanner)
            state = doc['scan_status'][scanner]
            if state == 'ok':
                assert isinstance(result.get(key), list), (project['name'], scanner, key)
            else:
                assert result.get('scan_status') == state, (project['name'], scanner)
                assert key not in result, (project['name'], scanner, 'fabricated empty report')
    print('VALIDATED: 30 project folders, exactly 3 JSON files each, all counts consistent.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', default='application')
    parser.add_argument('--manifest', default='projects/manifest.json')
    args = parser.parse_args()
    validate(Path(args.root), Path(args.manifest))


if __name__ == '__main__':
    main()
