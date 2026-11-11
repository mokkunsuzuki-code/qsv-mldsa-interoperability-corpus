#!/usr/bin/env python3
"""Append-only, one-case gate-first v0.2 SOURCE-ONLY candidate (UNEXECUTED).

Only OpenSSL / ML-DSA-44 / tg1 / tc1 / expected_valid=False is supported.
ACCEPT means a normalized EVIDENCE record, never a valid ML-DSA signature.
This is not a verifier for the legacy three-source v0.3 metadata-only PASS.
No network, no implicit source fetch, no hard-coded local filesystem root.
Explicit --run-one-shot requires separately authorized external preflight.
The v0.1 source had a local one-case PASS; v0.2 has NOT been executed.
There is no public API accepting caller-injected gate modules/policy/validator.
Hostile in-process callers and sys.modules/sys.path changes are unsupported.
"""
from __future__ import annotations
import argparse
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import zipfile

CORE_SHA = '99b8f20c4ee7b8215236d94382e70cfeb6d541f9cd4b8d13dd3f33da829ee808'
PIN_A03 = '8800ddc0779f2f31c15ec167c4e3fbc37afc6502bf2d8687665aa31872ecc0c5'
PIN_A04 = '665425e8237c6d76a8e3028a9c6d9d581e2c42552435c49bd20be476a1d7c10c'
PIN_L01 = '71bf8b7ced4744a28d0a7e8d302c66e591d52cbbf0288534e87d65694645f600'
PIN_POLICY = '789b938da2667c5afaf06edfd47dd8d25076f4bbe221c5339e03203204d9f013'
PIN_PROMPT = 'e2cba4589389756fa0bea1a7e6837138bf0a81f9d14234c9ee8f6d33caa1654e'
PIN_EXPECTED = 'e1d84ef1b2f35196278ab0b0ed6a46ec62cc03d2dfa92c564199e1999bfb8ea6'
PIN_N01 = '7707e41bd24dccbab58b474c2124bf0daf6eb7c9aae842933a0aafba70f3fc93'
PIN_FIXTURE = '11c9d28a211d1545bd0ba9b83da4ce101fb6be0bcf815063d7af905962825602'
PIN_CANONICAL = '920c71cbcf752c1b954536d2a1e2b1a331e41a97c5d00f42146dfb4ae528ac30'
PIN_LINEAGE = 'bead53b3ca4f475ead06d5d1c5ba99cfd98ed69c5e59cec7e62d88723325c289'
PIN_HIST_ADAPTER = '5a9adeeb92eef28abd5f3d5a6be516f886c7f8b8b656dfbddfb83e66ed9655e8'
PIN_HIST_RUNTIME = '07978755211bffcfe57f28ce6354292245a3a0af08d247c617c3f36378aa6b93'
CASE = {'case_id':'ML-DSA-44-tg1-tc1','parameter_set':'ML-DSA-44',
        'tg_id':1,'tc_id':1,'expected_valid':False}
SELECTORS = {'implementation_id':'openssl',**CASE}
CONSUMER_KEYS = frozenset(('implementation_id','repository','source_commit','source_tree',
    'lineage_sha256','historical_adapter_sha256','historical_runtime_executable_sha256',
    'historical_source_to_runtime_status','historical_provenance_class',
    'new_adapter_raw_sha256','new_adapter_identity_class'))
SHA_PINS = {
    'qsv_mldsa_acvp_inmemory_regenerator_v0_1.py': PIN_A04,
    'verify_qsv_mldsa_adapter_preacceptance_v0_4.py': PIN_A03,
    'qsv_mldsa_one_case_positive_baseline_launcher_candidate_v0_2.py': PIN_L01,
    'qsv_mldsa_gate_first_policy_v0_1.py': PIN_POLICY,
}

class SourceBoundBlocked(ValueError):
    """Fail-closed: never interpret as an accepted normalized evidence record."""

def require(ok: bool, reason: str) -> None:
    if not ok: raise SourceBoundBlocked(reason)

def digest(raw: bytes) -> str:
    require(type(raw) is bytes,'RAW_BYTES_REQUIRED')
    return hashlib.sha256(raw).hexdigest()

def pair_unique(pairs):
    out = {}
    for key,value in pairs:
        require(key not in out,'DUPLICATE_JSON_KEY')
        out[key]=value
    return out

def parse(raw: bytes):
    def bad_constant(_): raise SourceBoundBlocked('NONFINITE_JSON')
    def finite_float(token):
        x=float(token)
        require(math.isfinite(x),'NONFINITE_JSON')
        return x
    try:
        return json.loads(raw.decode('utf-8','strict'),object_pairs_hook=pair_unique,
                          parse_constant=bad_constant,parse_float=finite_float)
    except (UnicodeError,ValueError,RecursionError,OverflowError) as exc:
        raise SourceBoundBlocked('STRICT_JSON_INVALID') from exc

def render(record: dict) -> bytes:
    return (json.dumps(record,ensure_ascii=False,sort_keys=True,
                       allow_nan=False,separators=(',',':'))+'\n').encode('utf-8')

def safe_regular(path: Path, max_size: int) -> bytes:
    require(path.is_absolute(),'EXPLICIT_ABSOLUTE_INPUT_PATH_REQUIRED')
    require(not path.is_symlink() and path.is_file(),'INPUT_NOT_REGULAR_OR_SYMLINK')
    require(all(not q.is_symlink() for q in path.parents),'INPUT_PARENT_SYMLINK')
    st=path.stat()
    require(stat.S_ISREG(st.st_mode) and 0 < st.st_size <= max_size,'INPUT_SIZE_BOUND')
    with path.open('rb') as stream: raw=stream.read(max_size+1)
    require(len(raw)==st.st_size,'INPUT_CHANGED_DURING_READ')
    return raw

def _safe_zip_names(z: zipfile.ZipFile) -> None:
    names=z.namelist()
    require(len(names)==len(set(names)),'ZIP_DUPLICATE_ENTRY')
    for item in z.infolist():
        name=item.filename
        require(name and '\\' not in name and not name.startswith('/'),'ZIP_UNSAFE_PATH')
        require(all(x not in ('.','..','') for x in PurePosixPath(name).parts), 'ZIP_PATH_TRAVERSAL')
        require((item.external_attr >> 16) & 0o170000 != stat.S_IFLNK,'ZIP_SYMLINK')
        require(0 <= item.file_size <= 4_200_000,'ZIP_MEMBER_SIZE')
    require(z.testzip() is None,'ZIP_CRC')

def _read_member(z: zipfile.ZipFile, name: str, size: int, sha: str) -> bytes:
    require(name in z.namelist(),'ZIP_MEMBER_MISSING')
    item=z.getinfo(name)
    require(item.file_size==size and size <= 4_200_000,'ZIP_MEMBER_SIZE_MISMATCH')
    data=z.read(name)
    require(len(data)==size and digest(data)==sha,'ZIP_MEMBER_RAW_IDENTITY')
    return data

def load_core_snapshot(core_archive: Path):
    """Read selected 18 immutable roles from exact CORE (nested ZIP only if needed).

    No extraction to disk. This adapter never copies NIST vectors to its source tree.
    """
    core=safe_regular(core_archive,12_000_000)
    require(len(core)==8_495_356 and digest(core)==CORE_SHA,'CORE_RAW_NOT_PINNED')
    with zipfile.ZipFile(io.BytesIO(core)) as z:
        _safe_zip_names(z)
        require(len(z.namelist())==61,'CORE_ENTRY_COUNT')
        index=parse(z.read('qsp_qsv_reviewer_transport_index_v0_1.json'))
        rows=index.get('role_map')
        require(type(rows) is list and len(rows)==60,'ROLE_INDEX_INVALID')
        by_role={}
        for row in rows:
            role=row.get('role')
            require(type(role) is str and role not in by_role,'ROLE_DUPLICATE')
            by_role[role]=row
        def get(role):
            require(role in by_role,'UNPINNED_ROLE')
            row=by_role[role]
            size=row['expected_bytes'];sha=row['expected_sha256']
            require(type(size) is int and 0 < size <= 4_200_000 and
                    type(sha) is str and len(sha)==64,'ROLE_SHAPE')
            blob=row['scope_paths'].get('CORE_REVIEW')
            if blob is not None:
                require(blob=='blobs/'+sha,'BLOB_CONTENT_ADDRESS_MISMATCH')
                return _read_member(z,blob,size,sha)
            extraction=row.get('extraction',{})
            nested_role='iso_zip_'+extraction.get('iso_zip_filename','')
            require(nested_role in by_role,'NESTED_ORIGIN_UNAVAILABLE')
            raw_zip=get(nested_role)
            with zipfile.ZipFile(io.BytesIO(raw_zip)) as nested:
                _safe_zip_names(nested)
                return _read_member(nested,extraction['zip_member'],size,sha)
        raw_by_path={}
        for role in by_role:
            if role.startswith('runner_raw_'):
                raw_by_path[role[len('runner_raw_'):]]=get(role)
        require(len(raw_by_path)==18,'EXACT_EIGHTEEN_RAW_REQUIRED')
        mutated=get('r4_mutated_prompt_copy')
        return raw_by_path,mutated

def _load_verified_modules():
    """Only the future authorized entrypoint imports the actual pinned modules."""
    runtime=Path(__file__).resolve().parent
    require(runtime.is_dir() and not runtime.is_symlink(),'RUNTIME_DIR_UNTRUSTED')
    for name,pin in SHA_PINS.items():
        raw=safe_regular(runtime/name,120_000)
        require(digest(raw)==pin,'MODULE_RAW_PIN_MISMATCH:'+name)
    if str(runtime) not in sys.path: sys.path.insert(0,str(runtime))
    import qsv_mldsa_one_case_positive_baseline_launcher_candidate_v0_2 as l01
    import verify_qsv_mldsa_adapter_preacceptance_v0_4 as a03
    import qsv_mldsa_acvp_inmemory_regenerator_v0_1 as a04
    import qsv_mldsa_gate_first_policy_v0_1 as policy_mod
    return l01,a03,a04,policy_mod

def _consumer_from_historical(raw_by_path: dict, l01, adapter_hash: str):
    historical=l01.parse_json(raw_by_path['qsv/'+l01.CONSUMER])['consumer']
    source=historical['source_identity'];runtime=historical['runtime_identity']
    require(historical.get('implementation_id')=='openssl','CONSUMER_IMPL')
    require(historical.get('repository')=='https://github.com/openssl/openssl.git','CONSUMER_REPO')
    require(source.get('commit')=='aae016bfd52fcad2bc9657c2c782cfdf73b1ed5f' and
            source.get('tree')=='a8a306c000bc2426afd3264b2c41bc7223728475',
            'CONSUMER_SOURCE_PIN')
    require(runtime.get('executable_sha256')==PIN_HIST_RUNTIME and
            historical.get('source_to_runtime_binding',{}).get('status')=='incomplete',
            'CONSUMER_RUNTIME_PIN')
    consumer={'implementation_id':'openssl','repository':historical['repository'],
        'source_commit':source['commit'],'source_tree':source['tree'],
        'lineage_sha256':PIN_LINEAGE,'historical_adapter_sha256':PIN_HIST_ADAPTER,
        'historical_runtime_executable_sha256':PIN_HIST_RUNTIME,
        'historical_source_to_runtime_status':'incomplete',
        'historical_provenance_class':'CARRIED_FORWARD_NOT_INDEPENDENTLY_REPRODUCED',
        'new_adapter_raw_sha256':adapter_hash,
        'new_adapter_identity_class':'LOCAL_SELF_OBSERVED_UNATTESTED'}
    require(set(consumer)==CONSUMER_KEYS,'CONSUMER_EXACT_11_KEYS')
    return consumer

def _invoke_actual_a03(a03,a04,request,verified,authority,events,lane):
    calls={'a03':0,'a04':0}
    c03=a03.verify_preacceptance.__code__
    c04=a04.regenerate_from_verified_bytes.__code__
    def profile(frame,event,_arg):
        if event=='call':
            if frame.f_code is c03:calls['a03']+=1
            if frame.f_code is c04:calls['a04']+=1
    events.append({'lane':lane,'event':'A03_ENTER','prompt_sha256':digest(verified['prompt'])})
    sys.setprofile(profile)
    try:
        try: envelope=a03.verify_preacceptance(request,verified,authority)
        except a03.PreacceptanceBlocked as exc:
            events.append({'lane':lane,'event':'A03_REJECT','reason':str(exc)})
            return {'kind':'RAISED','exception_class':'PreacceptanceBlocked',
                'reason':str(exc),'envelope':None,'a03_calls':calls['a03'],
                'a04_calls':calls['a04']}
        events.append({'lane':lane,'event':'A03_PASS','decision':envelope.get('decision') if
                       type(envelope) is dict else 'NON_DICT'})
        return {'kind':'RETURNED','exception_class':None,'reason':None,
                'envelope':envelope,'a03_calls':calls['a03'],'a04_calls':calls['a04']}
    finally:sys.setprofile(None)

def _construct_positive(permit,policy,verified,env,consumer,adapter_sha,observed):
    """Private constructor: callable only with a gate-issued single-use permit."""
    policy.consume_construction_permit(permit)
    require(env['decision']=='PREACCEPTANCE_PASS','CONSTRUCTOR_NO_CURRENT_PASS')
    return {
        'schema':'qsv.mldsa.source-bound.accepted-evidence.v0.1',
        'acceptance_mode':'source_bound','selectors':dict(SELECTORS),
        'source_gate':{'status':'PREACCEPTANCE_PASS',
            'source_regeneration_performed':True,'same_verified_bytes_consumed':True,
            'published_fixture_byte_match':True,'a03_module_sha256':PIN_A03,
            'a04_regenerations_target_observed':observed['a04_calls'],
            'current_a03_envelope_sha256':digest(render(env)),
            'cached_r1_gate_used':False,'observation_class':'LOCAL_UNATTESTED'},
        'source_files':{
            role:{'role':role,'path':('gen-val/json-files/ML-DSA-sigVer-FIPS204/'+
                  ('prompt.json' if role=='prompt' else 'expectedResults.json')),
                  'raw_sha256':digest(verified[role])}
            for role in ('prompt','expected_results')},
        'normalized_result_source_binding':{
            'gate_status':'PREACCEPTANCE_PASS','source_regeneration_performed':True,
            'prompt_raw_sha256':digest(verified['prompt']),
            'expected_results_raw_sha256':digest(verified['expected_results'])},
        'historical_case':{'case_id':CASE['case_id'],
            'canonical_record_sha256':PIN_CANONICAL,'result_state':'expected_reject',
            'observed_acceptance':False,'new_sigver_executed':False},
        'consumer':consumer,
        'claim_boundary':{'historical_source_to_runtime_provenance':'INCOMPLETE',
            'third_party_attestation':False,'official_acceptance':False,
            'signature_crypto_acceptance_not_implied':True}
    }


def _write_exclusive(directory: Path,filename: str,raw: bytes) -> dict:
    require('/' not in filename and filename not in ('.','..'),'OUTPUT_NAME_UNSAFE')
    path=directory/filename
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as output:
        output.write(raw);output.flush();os.fsync(output.fileno())
    require(path.read_bytes()==raw,'OUTPUT_READBACK_MISMATCH')
    return {'filename':filename,'bytes':len(raw),'sha256':digest(raw)}

def run_one_shot(core_archive: Path,output_root: Path):
    """Only supported IO entrypoint, requiring separate human authorization.

    Fresh pinned input and module authority is loaded before binding a private
    lane closure for both positive and N01. v0.2 is NOT runtime verified.
    """
    require(output_root.is_absolute() and not output_root.exists(),'OUTPUT_ROOT_COLLISION')
    require(output_root.parent.is_dir() and not output_root.parent.is_symlink(),
            'OUTPUT_PARENT_UNSAFE')
    raw_by_path,mutated=load_core_snapshot(core_archive)
    require(len(mutated)==3125947 and digest(mutated)==PIN_N01,'N01_COPY_NOT_FIXED')
    original=raw_by_path['nist/gen-val/json-files/ML-DSA-sigVer-FIPS204/prompt.json']
    require(len(original)==len(mutated) and original[2987:2988]==b'4' and
            mutated[2987:2988]==b'5' and
            sum(a!=b for a,b in zip(original,mutated))==1,'N01_BYTE_DELTA_INVALID')
    l01,a03,a04,policy_module=_load_verified_modules()
    prepared=l01.prepare_one_case_inputs(raw_by_path)  # PINNED exact 18 Raw by L01
    require(prepared['request']=={'implementation_id':'openssl',
            'case_identity':CASE,'acceptance_mode':'source_bound',
            'source_bound_requested':True,'case_bindings':[CASE['case_id']]},
            'SELECTOR_OR_SOURCE_MODE_CHANGED')
    from jsonschema import Draft202012Validator
    root=Path(__file__).resolve().parent.parent
    result_schema=parse(safe_regular(root/'schemas/qsv-mldsa-source-bound-accepted-evidence-v0.1.schema.json',100_000))
    receipt_schema=parse(safe_regular(root/'schemas/qsv-mldsa-source-bound-attempt-receipt-v0.1.schema.json',100_000))
    Draft202012Validator.check_schema(result_schema)
    Draft202012Validator.check_schema(receipt_schema)
    result_validator=Draft202012Validator(result_schema)
    receipt_validator=Draft202012Validator(receipt_schema)
    adapter_sha=digest(safe_regular(Path(__file__).resolve(),100_000))
    consumer=_consumer_from_historical(raw_by_path,l01,adapter_sha)
    record,binding=l01.selected_record_and_binding(raw_by_path)
    require(record['result_state']=='expected_reject' and binding['case_identity']==CASE,
            'HISTORICAL_CASE_JOIN_FAILED')
    expected={'prompt_sha256':PIN_PROMPT,'expected_sha256':PIN_EXPECTED,
        'fixture_sha256':PIN_FIXTURE,'selectors':SELECTORS,'consumer':consumer,
        'canonical_sha256':PIN_CANONICAL}
    policy=policy_module.GateFirstPolicy(expected)
    events=[]
    # The raw-pinned dependencies are bound here, not supplied by lane callers.
    # This function does not attest to a hostile embedded Python interpreter.
    def _accept_lane(*, lane, verified):
        """Internal closure: real A03 precedes any normalized constructor."""
        require(lane in ('POSITIVE','NEGATIVE_N01'),'UNSUPPORTED_LANE')
        require(set(verified)=={'prompt','expected_results'} and
                all(type(v) is bytes for v in verified.values()),'RAW_SOURCE_ROLES')
        require(digest(verified['expected_results'])==PIN_EXPECTED,'EXPECTED_RESULTS_MISMATCH')
        expected={'prompt_sha256':PIN_PROMPT,'expected_sha256':PIN_EXPECTED,
            'fixture_sha256':PIN_FIXTURE,'selectors':SELECTORS,'consumer':consumer,
            'canonical_sha256':PIN_CANONICAL}
        # Policy never receives a caller-provided A03 PASS flag; observation is created here.
        ticket=policy.begin(lane,selectors=SELECTORS,consumer=consumer,unique_join=1,
                            canonical_sha256=PIN_CANONICAL,fixture_sha256=PIN_FIXTURE)
        events.append({'lane':lane,'event':'SUCCESSOR_ENTRY','prompt_sha256':digest(verified['prompt'])})
        gate=_invoke_actual_a03(a03,a04,prepared['request'],verified,prepared['authority'],events,lane)
        observation={**gate,'prompt_sha256':digest(verified['prompt']),
                     'expected_sha256':digest(verified['expected_results']),
                     'fixture_sha256':PIN_FIXTURE,'origin':'ACTUAL_A03_THIS_ENTRYPOINT'}
        outcome,permit=policy.after_actual_a03(ticket,observation)
        if outcome=='REJECT':
            require(lane=='NEGATIVE_N01' and permit is None,'NEGATIVE_NOT_REJECTED')
            events.append({'lane':lane,'event':'CONSTRUCTOR_NOT_CALLED'})
            return {'outcome':'REJECT','result':None,'constructor_calls':0,'gate':gate}
        require(lane=='POSITIVE' and outcome=='ACCEPT','POSITIVE_NOT_ACCEPTED')
        # A03 authoritative 12-record historical join before constructor.
        authority=prepared['authority']
        require(gate['envelope']['normalized_result_source_binding']['historical_canonical_sha256'] ==
                PIN_CANONICAL,'HISTORICAL_CANONICAL_NOT_GATE_BOUND')
        events.append({'lane':lane,'event':'NORMALIZED_CONSTRUCTOR_ENTER'})
        result=_construct_positive(permit,policy,verified,gate['envelope'],consumer,adapter_sha,gate)
        events.append({'lane':lane,'event':'NORMALIZED_CONSTRUCTOR_RETURN'})
        result_validator.validate(result)
        events.append({'lane':lane,'event':'RESULT_SCHEMA_PASS'})
        return {'outcome':'ACCEPT','result':result,'constructor_calls':1,'gate':gate}

    p=_accept_lane(lane='POSITIVE',verified=prepared['verified_sources'])
    require(p['outcome']=='ACCEPT' and p['constructor_calls']==1,'POSITIVE_NOT_ACCEPTED')
    negative_verified={**prepared['verified_sources'],'prompt':mutated}
    n=_accept_lane(lane='NEGATIVE_N01',verified=negative_verified)
    require(n['outcome']=='REJECT' and n['result'] is None and n['constructor_calls']==0 and
            n['gate']['reason']=='PINNED_SOURCE_DIGEST_MISMATCH','N01_NOT_EXACT_REJECT')
    policy.assert_outcomes(p['outcome'],n['outcome'],p['constructor_calls'],
                           n['constructor_calls'],1,0)
    events.append({'lane':'NEGATIVE_N01','event':'NEGATIVE_RECEIPT_PREPARED'})
    negative={'schema':'qsv.mldsa.source-bound.attempt-receipt.v0.1',
        'record_type':'NEGATIVE_REJECTION','lane':'NEGATIVE_N01',
        'status':'REJECT','exception_class':'PreacceptanceBlocked',
        'reason':'PINNED_SOURCE_DIGEST_MISMATCH','prompt_raw_sha256':PIN_N01,
        'expected_results_raw_sha256':PIN_EXPECTED,'accepted_result_count':0,
        'constructor_calls_target_observed':0,'a03_calls_target_observed':1,
        'a04_calls_target_observed':0}
    receipt_validator.validate(negative)
    positive_raw=render(p['result']);negative_raw=render(negative);trace_raw=render(events)
    combined={'schema':'qsv.mldsa.source-bound.attempt-receipt.v0.1',
        'record_type':'FINAL','lane':'TWO_LANE','status':'PASS_LOCAL_UNATTESTED',
        'positive_sha256':digest(positive_raw),'negative_sha256':digest(negative_raw),
        'trace_sha256':digest(trace_raw),'accepted_positive_results':1,
        'accepted_negative_results':0,'constructor_calls_target_observed':1,
        'a03_calls_target_observed':2,'a04_calls_target_observed':2,
        'historical_source_to_runtime_provenance':'INCOMPLETE',
        'third_party_attestation':False,'official_acceptance':False}
    receipt_validator.validate(combined)
    output_root.mkdir(mode=0o700)
    evidence=output_root/'evidence';evidence.mkdir(mode=0o700)
    for name,raw in [('positive.normalized_result.raw.json',positive_raw),
                     ('negative.rejection_receipt.raw.json',negative_raw),
                     ('source_bound.event_trace.raw.json',trace_raw),
                     ('source_bound.attempt_receipt.raw.json',render(combined))]:
        _write_exclusive(evidence,name,raw)
    return combined

def main(argv=None):
    p=argparse.ArgumentParser(description='One-case R1–R4 source-bound v0.2 SOURCE-ONLY; no execution authority')
    p.add_argument('--run-one-shot',action='store_true',help='requires separate explicit user authorization')
    p.add_argument('--core-archive',type=Path)
    p.add_argument('--output-root',type=Path)
    args=p.parse_args(argv)
    if not args.run_one_shot:
        print('NOT_EXECUTED: explicit --run-one-shot and external approval required')
        return 2
    require(args.core_archive is not None and args.output_root is not None,'ARGUMENTS_REQUIRED')
    require(args.core_archive.is_absolute() and args.output_root.is_absolute(),'ABSOLUTE_PATHS_REQUIRED')
    run_one_shot(args.core_archive,args.output_root)
    return 0

if __name__=='__main__':
    try: sys.exit(main())
    except Exception as exc:
        print('SOURCE_BOUND_BLOCKED:'+type(exc).__name__+':'+str(exc),file=sys.stderr)
        sys.exit(2)
