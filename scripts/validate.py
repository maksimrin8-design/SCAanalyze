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
        assert {x.name for x in folder.iterdir() if x.is_dir()} == {'osv','grype','default'}, project['name']
        doc = json.loads((folder/'default/reference.json').read_text(encoding='utf-8'))
        assert doc['project_id'] == project['id']
        assert doc['pinned_commit'] == project['ref']
        c = doc['counts']
        refs = doc['vulnerabilities']
        assert len(refs) == c['total'], project['name']
        assert c['osv'] == c['both'] + c['only_osv']
        assert c['grype'] == c['both'] + c['only_grype']
        assert c['total'] == (c['both'] + c['only_osv'] + c['only_grype'] +
                              c.get('independently_verified_but_not_detected', 0))
        for scanner in ('osv','grype'):
            scan = json.loads((folder/scanner/'findings.json').read_text(encoding='utf-8'))
            assert scan['project_id'] == project['id']
            assert scan['count'] == len(scan['findings']) == c[scanner]
            with (folder/scanner/'findings.csv').open(newline='',encoding='utf-8-sig') as f:
                assert len(list(csv.DictReader(f))) == c[scanner]
        with (folder/'default/reference.csv').open(newline='', encoding='utf-8-sig') as f:
            assert len(list(csv.DictReader(f))) == c['total']
    print('VALIDATED: 30 project folders, exactly 3 subfolders each, all counts consistent.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', default='application')
    parser.add_argument('--manifest', default='projects/manifest.json')
    args = parser.parse_args()
    validate(Path(args.root), Path(args.manifest))


if __name__ == '__main__':
    main()
