"""Inert Stage B probe source. Import performs no I/O. Default CLI is dry only."""
import argparse
import base64
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

OWNER = "shouishirakawa273-lab"
CANDIDATE = "jel-gov-b-candidate-20261018"
CONTROLLER = "jel-gov-b-controller-20261018"
ROOT = f"/repos/{OWNER}/{CANDIDATE}"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class Stop(Exception):
    pass


def safe_reason(status, data):
    # Exact recognized GitHub messages only; never retain message/raw body.
    messages = {
        "Resource not accessible by integration": "INTEGRATION_PERMISSION_DENIED",
        "Bad credentials": "AUTHENTICATION_FAILED",
        "Requires authentication": "AUTHENTICATION_REQUIRED",
        "API rate limit exceeded": "RATE_LIMITED",
        "Protected branch update failed": "PROTECTED_BRANCH_DENIED",
        "Pull Request is not mergeable": "MERGE_NOT_ALLOWED",
        "Base branch was modified. Review and try the merge again.": "STALE_BASE",
        "Validation Failed": "INVALID_PAYLOAD",
        "Not Found": "NOT_FOUND_UNPROVEN",
    }
    if 200 <= status < 300:
        return "HTTP_SUCCESS"
    return messages.get(data.get("message") if isinstance(data, dict) else None, "UNKNOWN_REASON")


def binding(path, operation):
    b = json.loads(Path(path).read_text(encoding="utf-8"))
    if b.get("armed") is not True or operation not in b.get("approvals", []):
        raise Stop("NOT_ARMED_OR_APPROVED")
    if (b.get("owner"), b.get("candidate"), b.get("controller")) != (OWNER, CANDIDATE, CONTROLLER):
        raise Stop("WRONG_RESOURCE")
    for key in ("controller_id", "candidate_id", "owner_id", "gate_app_id", "code_app_id", "gate_installation_id", "code_installation_id"):
        if type(b.get(key)) is not int or b[key] <= 0:
            raise Stop("UNBOUND_ID")
    if not re.fullmatch(r"[0-9a-f]{40}", b.get("control_sha") or "") or not re.fullmatch(r"[0-9a-f]{64}", b.get("manifest_sha256") or ""):
        raise Stop("UNBOUND_SOURCE")
    expected = {"GITHUB_REPOSITORY": f"{OWNER}/{CONTROLLER}", "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": b["control_sha"], "GITHUB_ACTOR": b.get("owner_login"), "GITHUB_ACTOR_ID": str(b["owner_id"])}
    if any(not value or os.environ.get(key) != value for key, value in expected.items()):
        raise Stop("CONTROL_IDENTITY_MISMATCH")
    if os.environ.get("B_APPROVED_MANIFEST") != b["manifest_sha256"]:
        raise Stop("MANIFEST_APPROVAL_MISMATCH")
    if type(b.get("api_limit")) is not int or not 1 <= b["api_limit"] <= 12:
        raise Stop("BUDGET_INVALID")
    return b


class Client:
    def __init__(self, token, limit):
        if not token:
            raise Stop("NO_TOKEN")
        self.token, self.left = token, limit
        self.opener = urllib.request.build_opener(NoRedirect())
        self.receipts = []

    def request(self, method, endpoint, payload=None):
        allowed = {("GET", ROOT), ("GET", ROOT + "/git/ref/heads/check-target"), ("GET", ROOT + "/git/ref/heads/main"), ("POST", ROOT + "/check-runs"), ("POST", ROOT + "/git/refs"), ("PUT", ROOT + "/contents/probe.txt"), ("POST", ROOT + "/pulls"), ("DELETE", "/installation/token"), ("PUT", ROOT + "/branches/main/protection"), ("PUT", ROOT + "/actions/workflows/legacy-health.yml/enable"), ("POST", ROOT + "/actions/workflows/legacy-health.yml/dispatches")}
        if re.fullmatch(re.escape(ROOT) + r"/pulls/[1-9][0-9]*(/reviews|/merge)?", endpoint):
            allowed.update({("GET", endpoint)} if not endpoint.endswith("/merge") else {("PUT", endpoint)})
        if re.fullmatch(re.escape(ROOT) + r"/git/refs/heads/(main|probe/negative)", endpoint):
            allowed.add(("PATCH", endpoint))
        if (method, endpoint) not in allowed or self.left <= 0:
            raise Stop("ENDPOINT_OR_BUDGET_DENIED")
        self.left -= 1
        raw = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
        req = urllib.request.Request("https://api.github.com" + endpoint, data=raw, method=method, headers={"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "jel-stage-b-fixed-probe", "Content-Type": "application/json"})
        try:
            with self.opener.open(req, timeout=20) as response:
                status, body = response.status, response.read(200001)
                request_id = response.headers.get("X-GitHub-Request-Id", "")
        except urllib.error.HTTPError as error:
            status, body = error.code, error.read(200001)
            request_id = error.headers.get("X-GitHub-Request-Id", "")
        except (urllib.error.URLError, TimeoutError):
            raise Stop("TRANSPORT_ERROR") from None
        if len(body) > 200000:
            raise Stop("RESPONSE_TOO_LARGE")
        try:
            data = json.loads(body) if body else {}
        except (ValueError, UnicodeError):
            raise Stop("NON_JSON_RESPONSE") from None
        if not re.fullmatch(r"[A-Fa-f0-9:]{8,128}", request_id):
            request_id = None
        reason = safe_reason(status, data)
        self.receipts.append({"method": method, "endpoint": endpoint, "status": status, "reason_code": reason, "github_request_id": request_id, "classification": "INDETERMINATE" if reason in ("UNKNOWN_REASON", "NOT_FOUND_UNPROVEN", "INVALID_PAYLOAD", "AUTHENTICATION_FAILED", "AUTHENTICATION_REQUIRED", "RATE_LIMITED", "STALE_BASE") or not request_id else "REQUIRES_CORROBORATION"})
        return status, data


def identity(client, b):
    status, data = client.request("GET", ROOT)
    if status != 200 or data.get("id") != b["candidate_id"] or data.get("full_name") != f"{OWNER}/{CANDIDATE}":
        raise Stop("REPOSITORY_ID_MISMATCH")


def bound_pr(client, b, require_approval=True):
    number = b.get("positive_pr")
    head = b.get("positive_head")
    if type(number) is not int or number <= 0 or not re.fullmatch(r"[0-9a-f]{40}", head or ""):
        raise Stop("PR_NOT_BOUND")
    status, pr = client.request("GET", ROOT + f"/pulls/{number}")
    if status != 200 or pr.get("head", {}).get("sha") != head or pr.get("base", {}).get("ref") != "check-target" or pr.get("draft") is not False or pr.get("user", {}).get("id") != b.get("code_bot_user_id"):
        raise Stop("PR_STALE_OR_AUTHOR_MISMATCH")
    if require_approval:
        status, reviews = client.request("GET", ROOT + f"/pulls/{number}/reviews")
        if status != 200 or not isinstance(reviews, list):
            raise Stop("REVIEW_UNAVAILABLE")
        owner_reviews = [r for r in reviews if r.get("user", {}).get("id") == b["owner_id"]]
        if not owner_reviews or owner_reviews[-1].get("state") != "APPROVED" or owner_reviews[-1].get("commit_id") != head or owner_reviews[-1].get("id") != b.get("owner_approval_review_id"):
            raise Stop("EXACT_HEAD_OWNER_APPROVAL_ABSENT")
    return pr


def run(args):
    if not args.execute:
        print(json.dumps({"mode": "DRY_NO_NETWORK", "operation": args.operation, "status": "NOT_RUN"}))
        return
    b = binding(args.binding, args.operation)
    client = Client(os.environ.get("B_INSTALLATION_TOKEN"), b["api_limit"])
    outcome = "ERROR"
    try:
        if args.operation == "revoke":
            status, _ = client.request("DELETE", "/installation/token")
            if status != 204:
                raise Stop("REVOCATION_NOT_CONFIRMED")
            outcome = "TOKEN_REVOKED"
        else:
            identity(client, b)
            if args.operation in ("seed", "checks-denial", "gate-positive"):
                sha = b.get("candidate_seed_sha")
                if args.operation == "gate-positive":
                    bound_pr(client, b)
                    sha = b["positive_head"]
                if not re.fullmatch(r"[0-9a-f]{40}", sha or ""):
                    raise Stop("SEED_SHA_UNBOUND")
                conclusion = "success" if args.operation == "gate-positive" else "failure"
                status, data = client.request("POST", ROOT + "/check-runs", {"name": "JEL-B / gate-final", "head_sha": sha, "status": "completed", "conclusion": conclusion, "output": {"title": "Stage B synthetic check", "summary": "check-target synthetic observation only; NOT a main merge permit"}})
                if args.operation == "checks-denial":
                    if 200 <= status < 300:
                        raise Stop("UNEXPECTED_CHECK_WRITE_SUCCESS")
                    # 403 alone is not proof: reviewer needs scoped-token positive control and App permission readback.
                    outcome = "DENIAL_OBSERVED_REQUIRES_CORROBORATION" if status == 403 and client.receipts[-1]["classification"] == "REQUIRES_CORROBORATION" else "INDETERMINATE"
                elif status != 201 or data.get("app", {}).get("id") != b["gate_app_id"] or data.get("head_sha") != sha:
                    raise Stop("SEED_SOURCE_MISMATCH")
                else:
                    outcome = "FAILURE_SEED_CREATED"
                    if args.operation == "seed":
                        status, data = client.request("POST", ROOT + "/check-runs", {"name": "JEL-B / owner-merge-permit", "head_sha": sha, "status": "completed", "conclusion": "failure", "output": {"title": "Merge prohibited", "summary": "Stage B never grants merge permission"}})
                        if status != 201 or data.get("app", {}).get("id") != b["gate_app_id"]:
                            raise Stop("MAIN_DENY_SEED_FAILED")
                    elif args.operation == "gate-positive":
                        bound_pr(client, b)
                        outcome = "CHECK_TARGET_SUCCESS_HEAD_RECONFIRMED_NO_MERGE"
            elif args.operation == "positive-pr":
                if b.get("positive_pr") is not None or b.get("positive_head") is not None:
                    raise Stop("PR_ALREADY_BOUND_NO_HEAD_UPDATE")
                status, data = client.request("GET", ROOT + "/git/ref/heads/check-target")
                if status != 200:
                    raise Stop("BASE_UNAVAILABLE")
                sha = data.get("object", {}).get("sha")
                if not re.fullmatch(r"[0-9a-f]{40}", sha or ""):
                    raise Stop("BASE_INVALID")
                status, _ = client.request("POST", ROOT + "/git/refs", {"ref": "refs/heads/probe/allowed", "sha": sha})
                if status != 201:
                    raise Stop("BRANCH_NOT_CREATED_NO_RETRY")
                status, data = client.request("PUT", ROOT + "/contents/probe.txt", {"message": "Stage B synthetic positive control", "branch": "probe/allowed", "content": base64.b64encode(b"Stage B synthetic fixture only\n").decode()})
                if status != 201:
                    raise Stop("SYNTHETIC_COMMIT_FAILED")
                head = data.get("commit", {}).get("sha")
                status, data = client.request("POST", ROOT + "/pulls", {"title": "Stage B synthetic positive control", "head": "probe/allowed", "base": "check-target", "body": "Owner approval is required. Freeze head after approval. Never merge.", "draft": False})
                if status != 201 or data.get("user", {}).get("type") != "Bot" or data.get("head", {}).get("sha") != head or data.get("base", {}).get("ref") != "check-target":
                    raise Stop("PR_BINDING_MISMATCH")
                # App login/id is recorded for independent comparison with installation identity, not guessed from owner.
                client.receipts.append({"positive_pr": data.get("number"), "head": head, "base": "check-target", "author_id": data.get("user", {}).get("id"), "author_login": data.get("user", {}).get("login"), "author_type": "Bot"})
                outcome = "PR_CREATED_OWNER_REVIEW_PENDING"
            elif args.operation == "negative-pr":
                bound_pr(client, b, require_approval=False)
                if b.get("negative_main_pr") is not None:
                    raise Stop("NEGATIVE_PR_ALREADY_BOUND")
                status, data = client.request("POST", ROOT + "/pulls", {"title": "Stage B synthetic protected-main negative control", "head": "probe/allowed", "base": "main", "body": "Synthetic rejection probe. No owner review or merge permission. Unexpected merge is FAIL; no rollback.", "draft": False})
                if status != 201 or data.get("user", {}).get("id") != b.get("code_bot_user_id") or data.get("head", {}).get("sha") != b["positive_head"] or data.get("base", {}).get("ref") != "main":
                    raise Stop("NEGATIVE_PR_BINDING_MISMATCH")
                client.receipts.append({"negative_main_pr": data.get("number"), "negative_main_head": b["positive_head"], "author_id": data.get("user", {}).get("id"), "base": "main"})
                outcome = "NEGATIVE_PR_CREATED_NO_REVIEW_NO_MERGE"
            elif args.operation in ("protected-push-denial", "admin-denial", "legacy-enable-denial", "legacy-dispatch-denial", "merge-denial"):
                if args.operation == "protected-push-denial":
                    # Only the bound synthetic positive head may be attempted on main; no force.
                    bound_pr(client, b, require_approval=False)
                    status, before = client.request("GET", ROOT + "/git/ref/heads/main")
                    if status != 200:
                        raise Stop("MAIN_PRESTATE_UNAVAILABLE")
                    status, _ = client.request("PATCH", ROOT + "/git/refs/heads/main", {"sha": b["positive_head"], "force": False})
                elif args.operation == "admin-denial":
                    # Same reviewed strong policy, never a weakening or bypass payload.
                    payload = json.loads(Path("admin-probe-payload.json").read_text(encoding="utf-8"))
                    expected_payload = {"required_status_checks": {"strict": True, "checks": [{"context": "JEL-B / gate-final", "app_id": "BIND_GATE_APP_ID"}, {"context": "JEL-B / owner-merge-permit", "app_id": "BIND_GATE_APP_ID"}]}, "enforce_admins": True, "required_pull_request_reviews": {"dismiss_stale_reviews": True, "required_approving_review_count": 1}, "restrictions": None, "allow_force_pushes": False, "allow_deletions": False, "lock_branch": True}
                    if payload != expected_payload or type(b.get("gate_app_id")) is not int or b["gate_app_id"] <= 0:
                        raise Stop("ADMIN_PAYLOAD_TEMPLATE_MISMATCH")
                    for check in payload["required_status_checks"]["checks"]:
                        check["app_id"] = b["gate_app_id"]
                    status, _ = client.request("PUT", ROOT + "/branches/main/protection", payload)
                elif args.operation == "legacy-enable-denial":
                    status, _ = client.request("PUT", ROOT + "/actions/workflows/legacy-health.yml/enable")
                elif args.operation == "legacy-dispatch-denial":
                    status, _ = client.request("POST", ROOT + "/actions/workflows/legacy-health.yml/dispatches", {"ref": "main"})
                else:
                    number = b.get("negative_main_pr")
                    head = b.get("negative_main_head")
                    if type(number) is not int or number <= 0 or not re.fullmatch(r"[0-9a-f]{40}", head or ""):
                        raise Stop("NEGATIVE_MAIN_PR_UNBOUND")
                    st, pr = client.request("GET", ROOT + f"/pulls/{number}")
                    if st != 200 or pr.get("head", {}).get("sha") != head or pr.get("base", {}).get("ref") != "main" or pr.get("merged") is not False:
                        raise Stop("NEGATIVE_MAIN_PR_MISMATCH")
                    # Owner must separately bind readback showing failure merge permit on this exact head.
                    if b.get("main_merge_deny_head") != head or b.get("main_protection_verified") is not True:
                        raise Stop("MAIN_DENY_EVIDENCE_UNBOUND")
                    status, _ = client.request("PUT", ROOT + f"/pulls/{number}/merge", {"sha": head, "merge_method": "merge"})
                if 200 <= status < 300:
                    raise Stop("UNEXPECTED_PROTECTED_WRITE_SUCCESS_NO_ROLLBACK")
                refusal = client.receipts[-1]
                if args.operation == "protected-push-denial":
                    st, after = client.request("GET", ROOT + "/git/ref/heads/main")
                    if st != 200 or before.get("object", {}).get("sha") != after.get("object", {}).get("sha"):
                        raise Stop("MAIN_CHANGED_STOP")
                outcome = "DENIAL_OBSERVED_REQUIRES_REASON_AND_POSITIVE_CONTROL" if status in (403, 405, 409, 422) and refusal["classification"] == "REQUIRES_CORROBORATION" else "INDETERMINATE"
    finally:
        print(json.dumps({"operation": args.operation, "outcome": outcome, "receipts": client.receipts}, separators=(",", ":")))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=["seed", "checks-denial", "positive-pr", "negative-pr", "gate-positive", "protected-push-denial", "admin-denial", "legacy-enable-denial", "legacy-dispatch-denial", "merge-denial", "revoke"])
    parser.add_argument("--binding", default="binding.example.json")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args()
    try:
        run(args)
    except (Stop, OSError, ValueError, KeyError) as error:
        print(json.dumps({"status": "STOP", "reason": str(error) if isinstance(error, Stop) else "LOCAL_INPUT_ERROR"}))
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
