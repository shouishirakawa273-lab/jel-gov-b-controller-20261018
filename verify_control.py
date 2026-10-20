"""External approved metadata verification. No network."""
import hashlib
import json
import os
from pathlib import Path


def main():
    raw = os.environ.get('B_EXECUTION_BINDING_JSON', '')
    if not raw or hashlib.sha256(raw.encode()).hexdigest() != os.environ.get('B_BINDING_SHA256'):
        raise SystemExit('STOP_BINDING_DIGEST')
    b = json.loads(raw)
    op = os.environ.get('OPERATION')
    expected = {'GITHUB_REPOSITORY': 'shouishirakawa273-lab/jel-gov-b-controller-20261018', 'GITHUB_REF': 'refs/heads/main', 'GITHUB_SHA': b.get('control_sha'), 'GITHUB_ACTOR': b.get('owner_login'), 'GITHUB_ACTOR_ID': str(b.get('owner_id'))}
    if b.get('armed') is not True or any(not v or os.environ.get(k) != v for k, v in expected.items()):
        raise SystemExit('STOP_CONTROL_BINDING')
    if b.get('reservation_approved') is not True or b.get('reservation_operation') != op or op not in b.get('approvals', []) or 'revoke' not in b.get('approvals', []):
        raise SystemExit('STOP_OPERATION_OR_BUDGET')
    entries = b.get('source_files', {})
    required = {'probe.py', 'verify_control.py', 'admin-probe-payload.json', '.github/workflows/app-probe.yml', '.github/workflows/canary.yml', 'policy.json', 'prompt.txt', 'schema.json', 'local-cases.json', 'local_cases.py', 'reservation.py'}
    if set(entries) != required:
        raise SystemExit('STOP_COVERAGE')
    canonical = json.dumps(entries, sort_keys=True, separators=(',', ':')).encode()
    if hashlib.sha256(canonical).hexdigest() != b.get('manifest_sha256'):
        raise SystemExit('STOP_MANIFEST_DIGEST')
    for name, digest in entries.items():
        if hashlib.sha256(Path(name).read_bytes()).hexdigest() != digest:
            raise SystemExit('STOP_SOURCE_CHANGED')
    Path('execution-binding.json').write_text(raw, encoding='utf-8')
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as output:
        for key in ('gate_client_id', 'code_client_id', 'manifest_sha256'):
            value = b.get(key)
            if not isinstance(value, str) or not value.isalnum():
                raise SystemExit('STOP_OUTPUT_VALUE')
            output.write(key + '=' + value + '\n')
    print('CONTROL_SOURCE_MATCH')


if __name__ == '__main__':
    main()
