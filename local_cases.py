"""Stage B-only synthetic controller evaluator; no network/candidate execution.

Prepared source only. Running these future cases does not prove GitHub denial.
"""
import hashlib
import json
from pathlib import PurePosixPath

EXPECTED = {'plan_sha':'a'*40,'control_sha':'b'*40,'policy_digest':'c'*64,'prompt_digest':'d'*64,'schema_digest':'e'*64,'producer_run':123,'head_sha':'f'*40,'producer':'synthetic-controller'}
ALLOWED_OPERATIONS = {'DOCUMENTATION_ONLY'}


def decide(candidate):
    if candidate.get('operation') not in ALLOWED_OPERATIONS:
        return 'FORBIDDEN_DENY'
    if any(candidate.get(k) != v for k,v in EXPECTED.items()):
        return 'STALE_DENY'
    path = candidate.get('artifact_path','')
    if not path or PurePosixPath(path).is_absolute() or '..' in PurePosixPath(path).parts or '\\' in path or ':' in path:
        return 'ARTIFACT_DENY'
    if candidate.get('content_digest') != hashlib.sha256(b'dummy A').hexdigest():
        return 'CONTENT_DENY'
    return 'MODEL_ALLOW'


def main():
    base = dict(EXPECTED,operation='DOCUMENTATION_ONLY',artifact_path='dummy.txt',content_digest=hashlib.sha256(b'dummy A').hexdigest())
    cases=[('positive',base,'MODEL_ALLOW')]
    for key in EXPECTED:
        changed=dict(base)
        changed[key]='mismatch'
        prefix = 'S05-tuple-' if key in ('producer_run', 'producer', 'head_sha') else 'S03-'
        cases.append((prefix+key,changed,'STALE_DENY'))
    cases.append(('S04-same-path-bytes',dict(base,content_digest=hashlib.sha256(b'dummy B').hexdigest()),'CONTENT_DENY'))
    for path in ('../unsafe','/absolute','x/../unsafe','C:\\unsafe'):
        cases.append(('S05-path',dict(base,artifact_path=path),'ARTIFACT_DENY'))
    for op in ('LOCKED','FROZEN','RESEARCH_EXECUTION'):
        cases.append(('S08-'+op,dict(base,operation=op),'FORBIDDEN_DENY'))
    failed=False
    for name,candidate,expected in cases:
        observed=decide(candidate)
        failed |= observed != expected
        print(json.dumps({'case_id':name,'evidence_type':'MODEL_DECISION','observed':observed,'expected':expected,'match':observed==expected,'github_or_os_proof':False}))
    if failed:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
