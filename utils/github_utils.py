import os
import sys
import time
import requests
from typing import Optional, List
from config import GITHUB_API


def get_token() -> str:
    tok = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not tok:
        sys.stderr.write("Error: GH_TOKEN or GITHUB_TOKEN environment variable is required.\n")
        sys.exit(2)
    return tok


def http_get(session: requests.Session, url: str, params: Optional[dict] = None, max_retries: int = 5) -> requests.Response:
    """GET with basic retry and rate-limit handling."""
    backoff = 1.5
    for attempt in range(max_retries):
        resp = session.get(url, params=params)
        if resp.status_code == 200:
            return resp

        # Rate limit
        if resp.status_code == 403 and resp.headers.get("X-RateLimit-Remaining") == "0":
            reset = resp.headers.get("X-RateLimit-Reset")
            now = int(time.time())
            sleep_for = max(5, int(reset) - now) if reset and reset.isdigit() else 60
            sys.stderr.write(f"Rate limited. Sleeping {sleep_for}s until reset...\n")
            time.sleep(sleep_for)
            continue

        # Secondary rate limit or abuse detection
        if resp.status_code in (403, 429):
            retry_after = resp.headers.get("Retry-After")
            if retry_after and retry_after.isdigit():
                sleep_for = int(retry_after)
            else:
                sleep_for = min(60, int(backoff ** (attempt + 1)))
            sys.stderr.write(f"HTTP {resp.status_code}. Backing off {sleep_for}s...\n")
            time.sleep(sleep_for)
            continue

        # Transient server errors
        if resp.status_code in (500, 502, 503, 504):
            sleep_for = min(60, int(backoff ** (attempt + 1)))
            sys.stderr.write(f"HTTP {resp.status_code}. Retrying in {sleep_for}s...\n")
            time.sleep(sleep_for)
            continue

        # Other errors - return to let caller decide
        return resp

    return resp


def list_all_repositories(session: requests.Session, org: str, repo_type: str) -> List[str]:
    """
    List all repositories in the organization based on the specified type.
    """
    repos = []
    page = 1
    while True:
        params = {
            "per_page": 100,
            "page": page,
            "type": repo_type if repo_type != "all" else None,
        }
        resp = http_get(session, f"{GITHUB_API}/orgs/{org}/repos", params=params)
        if resp.status_code != 200:
            sys.stderr.write(f"Failed to list repositories: {resp.status_code} {resp.text}\n")
            break
        data = resp.json()
        if not data:
            break
        repos.extend(repo["full_name"] for repo in data)
        page += 1
    return repos
