#!/usr/bin/env python3
"""Recreate application/<name>/{osv.json,grype.json,default.json} from scans.

The `default` reference is a PROVISIONAL union of tool observations, supplemented
by independently validated dependency+advisory rows. It is not an independent
complete truth set and MUST NOT be used to estimate unbiased recall/precision.
"""
from __future__ import annotations

import argparse
import csv
import json
import shutil
from collections import Counter, defaultdict
from pathlib import Path
from build_full_sca_table import component_key, inventory, read_csv, read_json

SEVERITY_ORDER = {'Unknown': 0, 'Low': 1, 'Medium': 2, 'High': 3, 'Critical': 4}


def severity(value):
    """Normalize Grype severity strings or OSV CVSS scores to common bands."""
    if isinstance(value, dict):
        value = value.get('score') or value.get('value') or ''
    text = str(value or '').strip().lower()
    labels = {'critical': 'Critical', 'high': 'High', 'medium': 'Medium',
              'moderate': 'Medium', 'low': 'Low', 'negligible': 'Low'}
    if text in labels:
        return labels[text]
    try:
        score = float(text)
    except ValueError:
        return 'Unknown'
    return ('Critical' if score >= 9 else 'High' if score >= 7 else
            'Medium' if score >= 4 else 'Low' if score > 0 else 'Unknown')


def write_json(path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')


def write_csv(path, columns, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('w', newline='', encoding='utf-8-sig') as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(rows)


def load_roots(raw_dir):
    roots = {}
    for path in sorted(raw_dir.rglob('project.json')):
        doc = read_json(path)
        if doc and doc.get('project_id'):
            roots[doc['project_id']] = path.parent
    return roots


def all_observation_metadata(root):
    """Index advisory severity and CWE, without claiming ground-truth verification."""
    keyed = defaultdict(list)
    if root is None:
        return keyed
    osv = read_json(root/'osv/result.json') or {}
    for item in osv.get('results', []) or []:
        for block in item.get('packages', []) or []:
            pkg = block.get('package') or {}
            key = component_key(pkg.get('name'), pkg.get('version'), pkg.get('ecosystem'))
            detail = {}
            for vuln in block.get('vulnerabilities', []) or []:
                ids = {str(x).lower() for x in [vuln.get('id')] + (vuln.get('aliases') or []) if x}
                db = vuln.get('database_specific') or {}
                cwes = {str(x).upper() for x in db.get('cwe_ids', []) or []}
                detail[str(vuln.get('id', '')).lower()] = (ids, severity(db.get('severity')), cwes)
            for group in block.get('groups', []) or []:
                ids = {str(x).lower() for x in (group.get('ids') or []) + (group.get('aliases') or []) if x}
                if not ids:
                    continue
                grade = severity(group.get('max_severity'))
                cwes = set()
                for alias_set, alt_grade, alt_cwes in detail.values():
                    if alias_set & ids:
                        cwes |= alt_cwes
                        if SEVERITY_ORDER[alt_grade] > SEVERITY_ORDER[grade]:
                            grade = alt_grade
                keyed[key].append((ids, grade, cwes))
    grype = read_json(root/'grype/result.json') or {}
    for item in grype.get('matches', []) or []:
        pkg = item.get('artifact') or {}
        name = pkg.get('name')
        if str(pkg.get('type', '')).lower() in ('java', 'java-archive', 'maven'):
            meta = pkg.get('metadata') or {}
            if meta.get('pomGroupID'):
                name = str(meta['pomGroupID']) + ':' + str(meta.get('pomArtifactID') or name)
        key = component_key(name, pkg.get('version'), pkg.get('type'))
        vuln = item.get('vulnerability') or {}
        ids = {str(x).lower() for x in [vuln.get('id')] + [j.get('id') for j in item.get('relatedVulnerabilities', []) or []] if x}
        cwes = set()
        for item_cwe in vuln.get('cwes', []) or []:
            code = item_cwe.get('cwe', '') if isinstance(item_cwe, dict) else str(item_cwe)
            if code:
                cwes.add(code.upper())
        keyed[key].append((ids, severity(vuln.get('severity')), cwes))
    return keyed


def decorate(v, meta):
    aliases = {x.lower() for x in v['all_identifiers'].split(';') if x}
    candidates = [x for x in meta.get(component_key(v['package'], v['version'], v['ecosystem']), []) if x[0] & aliases]
    grade = max((x[1] for x in candidates), key=lambda label: SEVERITY_ORDER[label], default='Unknown')
    cwes = sorted({code for _, _, codes in candidates for code in codes if code.startswith('CWE-')})
    return {'package': v['package'], 'installed_version': v['version'], 'ecosystem': v['ecosystem'],
            'vulnerability_id': v['vulnerability_id'], 'aliases': v['all_identifiers'].split(';'),
            'severity': grade, 'cwe_types': cwes,
            'found_by': [name for name in ('osv','grype') if v[name + '_status'] == 'Найдено'],
            'verification_status': ('project_and_advisory_verified' if v['reference_status'] == 'verified'
                                    else 'scanner_union_provisional'),
            'advisory_url': v['advisory_url'], 'project_evidence_url': v['reference_evidence'],
            'osv_dependency_source': v['osv_source'], 'grype_dependency_source': v['grype_source'],
            'notes': v['explanation']}


def generate(manifest, truth, raw_dir, out_dir, run_url=''):
    projects = manifest.get('projects')
    if not isinstance(projects, list) or len(projects) != 30:
        raise ValueError('Exactly 30 projects must be defined in manifest')
    if len({p['id'] for p in projects}) != 30 or len({p['name'] for p in projects}) != 30:
        raise ValueError('Duplicate project IDs/names')
    if any(not isinstance(p.get('ref'), str) or len(p['ref']) != 40 for p in projects):
        raise ValueError('Every project must use a pinned commit SHA')
    rows, diagnostics = inventory(manifest, truth, raw_dir)
    by_pid = defaultdict(list)
    for item in rows:
        by_pid[item['project_id']].append(item)
    diag_by_pid = {x['project_id']: x for x in diagnostics}
    roots = load_roots(raw_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    index = []
    for p in sorted(projects, key=lambda x: x['id']):
        pid, name = p['id'], p['name']
        root = roots.get(pid)
        dest = out_dir / name
        if not dest.resolve().is_relative_to(out_dir.resolve()):
            raise ValueError('Unsafe project directory: ' + name)
        dest.mkdir(parents=True, exist_ok=True)
        scan_status = diag_by_pid[pid]['scans']
        meta_index = all_observation_metadata(root)
        enriched = [decorate(r, meta_index) for r in by_pid[pid] if r['vulnerability_id']]
        enriched.sort(key=lambda x: (x['ecosystem'], x['package'], x['installed_version'], x['vulnerability_id']))
        duplicates = {(x['ecosystem'], x['package'], x['installed_version'], x['vulnerability_id']) for x in enriched}
        if len(duplicates) != len(enriched):
            raise AssertionError('Duplicated normalized vulnerability: ' + pid)
        counts = Counter()
        for item in enriched:
            found = item['found_by']
            if len(found) == 2:counts['both'] += 1
            elif found == ['osv']:counts['only_osv'] += 1
            elif found == ['grype']:counts['only_grype'] += 1
            else:counts['independently_verified_but_not_detected'] += 1
            counts['severity_' + item['severity']] += 1
            counts['verified'] += int(item['verification_status'] == 'project_and_advisory_verified')
        for k in ('both','only_osv','only_grype','independently_verified_but_not_detected','verified'):
            counts.setdefault(k, 0)
        counts['total'] = len(enriched)
        counts['osv'] = counts['both'] + counts['only_osv']
        counts['grype'] = counts['both'] + counts['only_grype']
        if any(scan_status[t] != 'ok' for t in ('osv','grype')):
            # Scanner errors are NOT false negatives; still retain verified independent entries.
            counts['comparison_valid'] = False
        else:
            counts['comparison_valid'] = True
        # Exactly three files per application in the FINAL archive. Internal
        # runner artifacts are allowed to contain auxiliary logs and metadata.
        # Keep successful native scanner JSON unchanged for direct inspection.
        # If a scan failed, preserve an explicit error object, not fabricated []
        # findings that could be mistaken for a clean scan.
        for scanner in ('osv', 'grype'):
            source = root / scanner / 'result.json' if root is not None else None
            target = dest / (scanner + '.json')
            status = scan_status[scanner]
            if status == 'ok':
                if source is None or not source.is_file():
                    raise AssertionError('Missing native scanner report despite OK: ' + pid)
                shutil.copyfile(source, target)
            else:
                scan_root = root / scanner if root is not None else None
                exit_file = scan_root / 'exit-code.txt' if scan_root is not None else None
                stderr_file = scan_root / 'stderr.log' if scan_root is not None else None
                write_json(target, {
                    'scanner': scanner, 'scan_status': status,
                    'project_id': pid, 'repository': p['repo'],
                    'pinned_commit': p['ref'], 'source_run': run_url,
                    'exit_code': exit_file.read_text(encoding='utf-8').strip()
                                 if exit_file and exit_file.is_file() else None,
                    'error_excerpt': stderr_file.read_text(encoding='utf-8', errors='replace')[-8000:]
                                     if stderr_file and stderr_file.is_file() else '',
                    'warning': 'Scanner did not complete: no result can be inferred.',
                })
        reference = {
            'schema_version': 1, 'project_id': pid, 'project': name, 'repository': p['repo'],
            'pinned_commit': p['ref'], 'source_run': run_url,
            'reference_type': 'scanner_union_plus_independently_verified_examples',
            'is_complete_independent_ground_truth': False,
            'methodology': ('Every finding reported by at least one analyzer, with CVE/GHSA aliases '
                            'merged, plus verified dependencies and advisories from ground-truth/verified.csv. '
                            'Scanner-only entries remain PROVISIONAL and vulnerabilities missed by both '
                            'analyzers may be absent. Do not infer unbiased recall or precision.'),
            'scan_status': scan_status, 'counts': dict(counts), 'vulnerabilities': enriched,
        }
        write_json(dest / 'default.json', reference)
        index.append({'id': pid, 'application': name, 'repository': p['repo'], 'commit': p['ref'],
                      'total_reference': counts['total'], 'osv': counts['osv'], 'grype': counts['grype'],
                      'both': counts['both'], 'only_osv': counts['only_osv'],
                      'only_grype': counts['only_grype'], 'verified': counts['verified'],
                      'critical': counts['severity_Critical'], 'high': counts['severity_High'],
                      'medium': counts['severity_Medium'], 'low': counts['severity_Low'],
                      'unknown': counts['severity_Unknown'],
                      'osv_status': scan_status['osv'], 'grype_status': scan_status['grype'],
                      'reference_file': name + '/default.json'})
    index_cols = list(index[0])
    write_csv(out_dir/'INDEX.csv', index_cols, index)
    # A transparent single CSV comparison summary for the course supervisor.
    # The single INDEX.csv lives only at archive root, not in app folders.
    print('Generated', len(index), 'application folders;', sum(x['total_reference'] for x in index), 'reference observations')
    return index


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', required=True)
    parser.add_argument('--ground-truth', required=True)
    parser.add_argument('--results-dir', required=True)
    parser.add_argument('--output-dir', default='application')
    parser.add_argument('--run-url', default='')
    args = parser.parse_args()
    manifest = read_json(Path(args.manifest))
    if manifest is None:
        raise ValueError('Invalid manifest JSON')
    truth = read_csv(Path(args.ground_truth))
    generate(manifest, truth, Path(args.results_dir), Path(args.output_dir), args.run_url)


if __name__ == '__main__':
    main()
