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


def check_rate_limit(session: requests.Session) -> dict:
    """Check current rate limit status."""
    resp = session.get(f"{GITHUB_API}/rate_limit")
    if resp.status_code == 200:
        return resp.json()
    return {}


def wait_for_rate_limit_reset(session: requests.Session, resource: str = "core") -> None:
    """
    Wait until the rate limit resets for the specified resource.
    """
    rate_info = check_rate_limit(session)
    if not rate_info:
        sys.stderr.write("Could not check rate limit, waiting 60s...\n")
        time.sleep(60)
        return
    
    resources = rate_info.get("resources", {})
    resource_info = resources.get(resource, {})
    
    remaining = resource_info.get("remaining", 0)
    reset_time = resource_info.get("reset", 0)
    
    if remaining == 0:
        now = int(time.time())
        sleep_duration = max(5, reset_time - now + 5)  # Add 5s buffer
        sys.stderr.write(f"Rate limit exhausted for '{resource}'. Waiting {sleep_duration}s until reset...\n")
        time.sleep(sleep_duration)
    elif remaining < 10:
        sys.stderr.write(f"Rate limit low ({remaining} remaining). Slowing down requests...\n")
        time.sleep(2)


def http_get(session: requests.Session, url: str, params: Optional[dict] = None, max_retries: int = 5, suppress_404: bool = False) -> requests.Response:
    """
    GET with comprehensive retry and rate-limit handling.
    
    Implements:
    - Primary rate limit detection and handling
    - Secondary rate limit (abuse detection) handling
    - Exponential backoff for transient errors
    - Proactive rate limit checking for search endpoints
    """
    backoff = 1.5
    
    # Proactive rate limit check for search API
    if url and "search" in url:
        wait_for_rate_limit_reset(session, "search")
    
    for attempt in range(max_retries):
        try:
            resp = session.get(url, params=params, timeout=30)
        except requests.exceptions.Timeout:
            sleep_for = min(60, int(backoff ** (attempt + 1)))
            sys.stderr.write(f"Request timeout. Retrying in {sleep_for}s...\n")
            time.sleep(sleep_for)
            continue
        except requests.exceptions.RequestException as e:
            sys.stderr.write(f"Request error: {e}. Retrying...\n")
            time.sleep(5)
            continue
        
        if resp.status_code == 200:
            return resp

        # Primary rate limit (403 with X-RateLimit-Remaining: 0)
        if resp.status_code == 403:
            remaining = resp.headers.get("X-RateLimit-Remaining")
            
            if remaining == "0":
                reset = resp.headers.get("X-RateLimit-Reset")
                now = int(time.time())
                sleep_for = max(5, int(reset) - now + 5) if reset and reset.isdigit() else 60
                sys.stderr.write(f"Primary rate limit hit. Sleeping {sleep_for}s until reset...\n")
                time.sleep(sleep_for)
                continue
            
            # Secondary rate limit (abuse detection)
            retry_after = resp.headers.get("Retry-After")
            if retry_after and retry_after.isdigit():
                sleep_for = int(retry_after) + 5  # Add buffer
                sys.stderr.write(f"Secondary rate limit (403). Sleeping {sleep_for}s as indicated by Retry-After...\n")
                time.sleep(sleep_for)
                continue
            
            # Generic 403 without clear rate limit headers
            sleep_for = min(120, int(backoff ** (attempt + 2)))
            sys.stderr.write(f"HTTP 403 (possible abuse detection). Backing off {sleep_for}s...\n")
            time.sleep(sleep_for)
            continue

        # Explicit rate limit response (429)
        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After")
            if retry_after and retry_after.isdigit():
                sleep_for = int(retry_after) + 5
            else:
                sleep_for = min(120, int(backoff ** (attempt + 2)))
            sys.stderr.write(f"HTTP 429 rate limit. Backing off {sleep_for}s...\n")
            time.sleep(sleep_for)
            continue

        # Transient server errors (5xx)
        if resp.status_code in (500, 502, 503, 504):
            sleep_for = min(60, int(backoff ** (attempt + 1)))
            sys.stderr.write(f"HTTP {resp.status_code} server error. Retrying in {sleep_for}s...\n")
            time.sleep(sleep_for)
            continue

        # Handle 404 (suppress if requested)
        if resp.status_code == 404:
            if not suppress_404:
                sys.stderr.write(f"HTTP 404 client error: {resp.text[:200]}\n")
            return resp

        # Other client errors that shouldn't be retried (4xx except 403, 429, 404)
        if 400 <= resp.status_code < 500:
            sys.stderr.write(f"HTTP {resp.status_code} client error: {resp.text[:200]}\n")
            return resp

        # Other unexpected errors
        sys.stderr.write(f"HTTP {resp.status_code}: {resp.text[:200]}\n")
        return resp

    sys.stderr.write(f"Max retries ({max_retries}) exceeded for {url}\n")
    return resp


def list_all_repositories(session: requests.Session, account: str, repo_type: str, include_archived: bool = False) -> List[str]:  # NUEVO: parámetro
    """
    List all repositories for a GitHub user or organization based on the specified type.
    Includes rate limit awareness.
    """
    repos = []
    page = 1
    archived_count = 0

    # Determine if the account is a user or an organization
    resp = http_get(session, f"{GITHUB_API}/users/{account}")
    if resp.status_code != 200:
        sys.stderr.write(f"Failed to determine account type: {resp.status_code} {resp.text}\n")
        return repos
    
    user_data = resp.json()
    is_org = user_data.get('type') == 'Organization'

    # Use the appropriate endpoint
    endpoint = f"{GITHUB_API}/orgs/{account}/repos" if is_org else f"{GITHUB_API}/users/{account}/repos"

    while True:
        params = {
            "per_page": 100,
            "page": page,
        }
        
        # Add type filter if specified
        if repo_type != "all":
            params["type"] = repo_type
        
        resp = http_get(session, endpoint, params=params)
        
        if resp.status_code != 200:
            sys.stderr.write(f"Failed to list repositories: {resp.status_code} {resp.text}\n")
            break
            
        data = resp.json()
        if not data:
            break
        
        for repo in data:
            if repo.get("archived", False):
                archived_count += 1
                if not include_archived:
                    continue  # Skip archived repos
            repos.append(repo["full_name"])
        
        page += 1
        
        # Small delay between pages to be respectful
        if len(data) == 100:  # Only delay if there might be more pages
            time.sleep(0.5)
    
    if archived_count > 0:
        if include_archived:
            sys.stderr.write(f"Found {archived_count} archived repositories (included in scan)\n")
        else:
            sys.stderr.write(f"Excluded {archived_count} archived repositories from scan\n")
    
    return repos