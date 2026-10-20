"""Future local concurrency fixture: one slot via OS exclusive file creation.

Not a shared GitHub cross-run budget service. Execute two independent processes
with the SAME new --directory and --slot one. No auto deletion/release.
"""
import argparse
import json
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--directory', required=True)
    p.add_argument('--slot', choices=['one'], required=True)
    p.add_argument('--execute', action='store_true')
    args = p.parse_args()
    if not args.execute:
        print('{"status":"NOT_RUN","network":0}')
        return
    directory = Path(args.directory).resolve()
    if directory.name != 'stage-b-reservation-fixture' or not directory.is_dir():
        raise SystemExit('STOP_NEW_FIXTURE_DIRECTORY_REQUIRED')
    try:
        with (directory / 'one.reserved').open('x', encoding='utf-8') as output:
            output.write('synthetic slot consumed\n')
        verdict = 'RESERVED'
    except FileExistsError:
        verdict = 'DENIED_ALREADY_RESERVED'
    print(json.dumps({'evidence_type':'LOCAL_OS_EXCLUSIVE_CREATE','result':verdict,'not_github_budget':True}))


if __name__ == '__main__':
    main()
