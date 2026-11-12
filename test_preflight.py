import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import preflight as p


class PreflightTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def put(self, name, data=b'x'):
        (self.root/name).write_bytes(data)

    def audit(self, **kw):
        return p.audit(self.root, kw.pop('pattern', 'shot.{frame:04d}.exr'),
                       kw.pop('start', 1), kw.pop('end', 3), **kw)

    def test_clean_and_no_mutation(self):
        for n in range(1, 4): self.put(f'shot.{n:04d}.exr')
        before = [(f.name, f.read_bytes(), f.stat().st_mtime_ns) for f in sorted(self.root.iterdir())]
        self.assertEqual(p.exit_code(self.audit()), 0)
        self.assertEqual(before, [(f.name, f.read_bytes(), f.stat().st_mtime_ns) for f in sorted(self.root.iterdir())])

    def test_missing_both_boundaries_and_interior(self):
        r = self.audit()
        self.assertEqual([x['position'] for x in r['missing']], ['boundary','interior','boundary'])
        self.assertEqual(p.exit_code(r), 1)

    def test_zero_unexpected_padding_duplicates(self):
        for name in ['shot.0001.exr', 'shot.1.exr', 'shot.+0001.exr', 'shot.0004.exr']:
            self.put(name)
        self.put('shot.0002.exr', b'')
        r = self.audit()
        self.assertEqual({f['kind'] for f in r['findings']}, {'empty_file','unexpected_frame','noncanonical_name','duplicate_frame'})
        self.assertEqual([f['frame'] for f in r['missing']], [3])

    def test_variant_does_not_fill_canonical_gap(self):
        self.put('shot.1.exr')
        self.assertEqual(len(self.audit(start=1,end=1)['missing']),1)

    def test_negative_and_step(self):
        for n in [-2,0,2]: self.put(f'shot.{n:04d}.exr')
        self.assertEqual(p.exit_code(self.audit(start=-2,end=2,step=2)),0)
        self.put('shot.0001.exr')
        self.assertIn('unexpected_frame', [x['kind'] for x in self.audit(start=-2,end=2,step=2)['findings']])

    def test_invalid_range(self):
        for args in [dict(step=0),dict(step=-1),dict(start=3,end=1),dict(end=4,step=2),
                     dict(start=0,end=1_000_000),dict(start=-(2**63)),dict(end=2**63)]:
            with self.subTest(args=args), self.assertRaises(p.InvalidInput): self.audit(**args)

    def test_invalid_patterns(self):
        for pattern in ['../{frame}', '/{frame}', '{frame!r}', '{frame:{x}}', '{other}',
                        '{frame}{frame}', '{frame:04x}', '{frame:033d}', 'a\\{frame}', '{frame:00d}']:
            with self.subTest(pattern=pattern), self.assertRaises(p.InvalidInput): self.audit(pattern=pattern)

    def test_literal_regex_and_unpadded(self):
        self.put('[x].-1.exr')
        self.put('x.-1.exr')
        r=self.audit(pattern='[x].{frame}.exr',start=-1,end=-1)
        self.assertEqual(p.exit_code(r),0)
        self.assertEqual(len(r['inventory']),1)

    def test_oversized_numeric_name_is_incomplete(self):
        self.put('shot.' + '1'*129 + '.exr')
        r = self.audit()
        self.assertEqual(p.exit_code(r), 2)
        self.assertIn('metadata not inspected', r['errors'][0]['reason'])

    def test_directory_missing(self):
        r=p.audit(self.root/'absent','{frame}',1,1)
        self.assertEqual(p.exit_code(r),2)
        self.assertEqual(r['missing'],[])

    @unittest.skipUnless(hasattr(os,'symlink'), 'requires symlinks')
    def test_symlink_entry_and_directory(self):
        target=self.root/'outside';target.write_bytes(b'not opened')
        (self.root/'shot.0001.exr').symlink_to(target)
        self.assertEqual(p.exit_code(self.audit()),2)
        link=self.root/'dirlink';link.symlink_to(self.root,target_is_directory=True)
        self.assertEqual(p.exit_code(p.audit(link,'{frame}',1,1)),2)

    def test_nonregular(self):
        (self.root/'shot.0001.exr').mkdir()
        self.assertEqual(p.exit_code(self.audit()),2)

    def test_metadata_failure(self):
        self.put('shot.0001.exr')
        original=os.lstat
        def fail(path,*a,**kw):
            if str(path).endswith('shot.0001.exr'): raise PermissionError(13,'denied')
            return original(path,*a,**kw)
        with patch('preflight.os.lstat',side_effect=fail): r=self.audit()
        self.assertEqual(p.exit_code(r),2)
        self.assertIn('PermissionError',r['errors'][0]['reason'])

    def test_scan_failure(self):
        with patch('preflight.os.scandir',side_effect=PermissionError(13,'denied')): r=self.audit()
        self.assertEqual(p.exit_code(r),2)

    def cli(self,*args):
        return subprocess.run([sys.executable,str(Path(p.__file__)),str(self.root),
            '--pattern','shot.{frame:04d}.exr','--start','1','--end','1',*args],capture_output=True,text=True)

    def test_cli_json_deterministic_and_codes(self):
        a=self.cli('--json');b=self.cli('--json')
        self.assertEqual(a.returncode,1);self.assertEqual(a.stdout,b.stdout)
        self.assertTrue(json.loads(a.stdout)['complete'])
        self.put('shot.0001.exr')
        self.assertEqual(self.cli('--json').returncode,0)
        invalid=self.cli('--step','0','--json')
        self.assertEqual(invalid.returncode,2)
        self.assertFalse(json.loads(invalid.stdout)['complete'])
        self.assertEqual(self.cli('--step','garbage').returncode,2)

    def test_human_cli(self):
        self.assertIn("missing boundary: 'shot.0001.exr'",self.cli().stdout)
        self.put('shot.0001.exr')
        self.assertIn('CLEAN',self.cli().stdout)


if __name__=='__main__': unittest.main()
