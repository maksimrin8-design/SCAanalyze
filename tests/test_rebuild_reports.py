import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from rebuild_reports import generate, severity
from validate import validate


class RebuildTests(unittest.TestCase):
    def test_severity_bands(self):
        self.assertEqual('Critical', severity(9.5))
        self.assertEqual('High', severity(7.3))
        self.assertEqual('Medium', severity(5.1))
        self.assertEqual('Low', severity(2.0))
        self.assertEqual('Unknown', severity(''))

    def test_30_project_layout_with_missing_scans(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            manifest={'projects':[{'id':f'P{i:03}', 'name':f'project-{i:03}',
                                   'repo':'example/repo', 'ref':'a'*40} for i in range(1,31)]}
            rows=[]
            result=generate(manifest, rows, root/'missing', root/'application', 'https://example.test/run')
            self.assertEqual(30, len(result))
            validate(root/'application', self._write_manifest(root,manifest))
            self.assertEqual('missing_artifact',result[0]['osv_status'])

    def test_provisional_and_verified_are_separate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            manifest={'projects':[{'id':f'P{i:03}', 'name':f'project-{i:03}',
                                   'repo':'example/repo', 'ref':'a'*40} for i in range(1,31)]}
            raw=root/'raw'/'scan-001'/'application'/'project-001'
            for scanner in ('osv','grype'):
                (raw/scanner).mkdir(parents=True)
            (raw/'project.json').write_text(json.dumps({'project_id':'P001'}))
            (raw/'osv/exit-code.txt').write_text('1')
            (raw/'grype/exit-code.txt').write_text('0')
            (raw/'osv/result.json').write_text(json.dumps({'results':[{'packages':[
                {'package':{'name':'alpha','version':'1.0','ecosystem':'npm'},
                 'vulnerabilities':[{'id':'GHSA-aaaa-bbbb-cccc', 'aliases':['CVE-2026-1111']}],
                 'groups':[{'ids':['GHSA-aaaa-bbbb-cccc'],'aliases':['CVE-2026-1111']}]}]}]}))
            (raw/'grype/result.json').write_text(json.dumps({'matches':[{'artifact':{
                'name':'alpha','version':'1.0','type':'npm'},
                'vulnerability':{'id':'CVE-2026-1111','severity':'High'}}]}))
            truth=[{'project_id':'P001','package':'different', 'version':'2.0','ecosystem':'npm',
                    'vulnerability_ids':'CVE-2026-2222','status':'verified',
                    'evidence_url':'https://github.com/example/repo/blob/aaaa/lockfile',
                    'notes':'manually verified'}]
            table=generate(manifest, truth, root/'raw', root/'application')
            docs=json.loads((root/'application/project-001/default/reference.json').read_text())
            findings=docs['vulnerabilities']
            self.assertEqual(2,len(findings))
            self.assertEqual(1,sum(x['verification_status']=='project_and_advisory_verified' for x in findings))
            self.assertEqual(1,sum(x['verification_status']=='scanner_union_provisional' for x in findings))
            self.assertEqual(1,docs['counts']['both'])
            self.assertEqual(1,docs['counts']['independently_verified_but_not_detected'])
            validate(root/'application',self._write_manifest(root,manifest))
            # The final ZIP must contain genuine unmodified native scanner reports.
            self.assertTrue((root/'application/project-001/osv/result.json').is_file())
            self.assertTrue((root/'application/project-001/grype/result.json').is_file())
            self.assertEqual('ok', json.loads(
                (root/'application/project-001/osv/scan-status.json').read_text())['status'])
            self.assertEqual('ok', json.loads(
                (root/'application/project-001/grype/scan-status.json').read_text())['status'])

    @staticmethod
    def _write_manifest(root,manifest):
        p=root/'manifest.json'
        p.write_text(json.dumps(manifest))
        return p


if __name__=='__main__':
    unittest.main()
