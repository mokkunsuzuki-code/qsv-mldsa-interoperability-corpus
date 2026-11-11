"""v0.2 standard discovery tests: synthetic schemas and static AST only.

No real P01/N01, no environment-variable launch, no CORE archive, and no
Adapter/A03/A04/L01 imports. Real tests require a separate fixed Supervisor.
"""
from __future__ import annotations
import ast
import copy
import json
from pathlib import Path
import unittest
from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / 'schemas/qsv-mldsa-source-bound-accepted-evidence-v0.1.schema.json'
ADAPTER = ROOT / 'runtime/qsv_mldsa_source_bound_gate_first_adapter_v0_2.py'


def synthetic_schema():
    result = json.loads(SCHEMA.read_text(encoding='utf-8'))
    Draft202012Validator.check_schema(result)
    return result


def synthetic_consumer():
    props = synthetic_schema()['properties']['consumer']['properties']
    return {k: p['const'] if 'const' in p else 'a' * 64 for k,p in props.items()}


class PureSourceContractTests(unittest.TestCase):
    def test_exact_eleven_fields(self):
        s = synthetic_schema()['properties']['consumer']
        self.assertEqual(len(s['required']), 11)
        self.assertFalse(s['additionalProperties'])
        self.assertEqual(set(s['properties']), set(s['required']))
        Draft202012Validator(s).validate(synthetic_consumer())

    def test_wrong_consumer_identity_rejected(self):
        s = synthetic_schema()['properties']['consumer']
        for mode in ('missing','extra','commit','tree','lineage'):
            sample = copy.deepcopy(synthetic_consumer())
            if mode == 'missing': sample.pop('lineage_sha256')
            if mode == 'extra': sample['untrusted_field'] = 'invented'
            if mode == 'commit': sample['source_commit'] = '0' * 40
            if mode == 'tree': sample['source_tree'] = '0' * 40
            if mode == 'lineage': sample['lineage_sha256'] = '0' * 64
            with self.subTest(mode=mode), self.assertRaises(ValidationError):
                Draft202012Validator(s).validate(sample)

    def test_no_target_or_gate_import_or_launch(self):
        tree = ast.parse(Path(__file__).read_text(encoding='utf-8'))
        imports = [n for n in ast.walk(tree) if isinstance(n,(ast.Import,ast.ImportFrom))]
        allnames = [a.name for n in imports for a in n.names]
        self.assertFalse(any(x.startswith(('qsv_mldsa_source_bound_gate_first_adapter',
          'verify_qsv_mldsa_adapter_preacceptance','qsv_mldsa_acvp_inmemory_regenerator',
          'qsv_mldsa_one_case_positive_baseline_launcher')) for x in allnames))
        self.assertFalse(any(isinstance(n,ast.Attribute) and n.attr in
          ('run_one_shot','verify_preacceptance','regenerate_from_verified_bytes')
          for n in ast.walk(tree)))

    def test_private_lane_and_prepared_event(self):
        tree = ast.parse(ADAPTER.read_text(encoding='utf-8'))
        top = {n.name:n for n in tree.body if isinstance(n,ast.FunctionDef)}
        self.assertNotIn('successor_acceptance_entrypoint', top)
        self.assertEqual(len([n for n in top['run_one_shot'].body
          if isinstance(n,ast.FunctionDef) and n.name == '_accept_lane']),1)
        content = ADAPTER.read_text(encoding='utf-8')
        self.assertIn("'NEGATIVE_RECEIPT_PREPARED'",content)
        self.assertNotIn("'NEGATIVE_RECEIPT_SAVED'",content)


if __name__=='__main__':
    unittest.main()
