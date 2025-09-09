#!/usr/bin/env python3
"""
Scan a GitHub organization for package-lock.json files and report occurrences
of specific packages at specific versions. Outputs Markdown to stdout.

Requirements:
  - Python 3.8+
  - requests 2.x  (pip install requests)

Authentication:
  - Uses GH_TOKEN or GITHUB_TOKEN environment variable.

Usage:
  python gh_lock_scan.py --org <org_name> --versions versions.txt [--debug] > report.md

versions.txt format (one per line):
  ansi-styles@6.2.2
  debug@4.4.2
  ...
"""

import argparse
import base64
import json
import os
import sys
import time
from typing import Dict, List, Tuple, Set, Iterable, Optional

import requests


GITHUB_API = "https://api.github.com"


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


def parse_versions_file(path: str) -> List[Tuple[str, str]]:
    """
    Parse a versions file with lines like:
      package@1.2.3
    Supports scoped packages: @scope/name@1.2.3
    """
    targets: List[Tuple[str, str]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "@@" in line:
                raise ValueError(f"Invalid line (contains '@@'): {line}")
            if "@" not in line:
                raise ValueError(f"Invalid line (missing @version): {line}")
            name, version = line.rsplit("@", 1)
            name = name.strip()
            version = version.strip()
            if not name or not version:
                raise ValueError(f"Invalid line (empty name or version): {line}")
            targets.append((name, version))
    return targets


def derive_name_from_path_key(path_key: str) -> Optional[str]:
    """
    Given a 'packages' key from lockfile v2 like:
      "", "node_modules/chalk", "node_modules/@scope/name", "node_modules/a/node_modules/b"
    derive the package name (e.g., chalk, @scope/name, b).
    """
    if not path_key:
        return None
    parts = path_key.split("node_modules/")
    tail = parts[-1] if parts else path_key
    tail = tail.strip("/")

    if not tail:
        return None

    if tail.startswith("@"):
        segs = tail.split("/")
        if len(segs) >= 2:
            return f"{segs[0]}/{segs[1]}"
        return tail
    else:
        return tail.split("/")[0]


def collect_occurrences_from_v2(lock: dict) -> List[Tuple[str, str, str]]:
    """
    For lockfileVersion >= 2, the 'packages' object lists all installed packages.
    Returns list of (name, version, where) where 'where' is the packages key.
    """
    occ: List[Tuple[str, str, str]] = []
    packages = lock.get("packages")
    if not isinstance(packages, dict):
        return occ
    for where, meta in packages.items():
        if not isinstance(meta, dict):
            continue
        name = meta.get("name") or derive_name_from_path_key(where or "")
        version = meta.get("version")
        if name and version:
            occ.append((name, str(version), where or "(root)"))
    return occ


def collect_occurrences_from_v1(lock: dict) -> List[Tuple[str, str, str]]:
    """
    For lockfileVersion 1 (npm v6), recursively traverse 'dependencies'.
    Returns list of (name, version, where) where 'where' is a pseudo path.
    """
    occ: List[Tuple[str, str, str]] = []
    deps = lock.get("dependencies")
    if not isinstance(deps, dict):
        return occ

    def walk(dep_dict: dict, lineage: List[str]) -> None:
        for name, meta in dep_dict.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get("version")
            where = "/".join(lineage + [name]) if lineage else name
            if version:
                occ.append((name, str(version), where))
            sub = meta.get("dependencies")
            if isinstance(sub, dict):
                walk(sub, lineage + [name])

    walk(deps, [])
    return occ


def collect_occurrences(lock: dict) -> List[Tuple[str, str, str]]:
    """
    Returns occurrences list of (name, version, where) from a package-lock.json.
    Handles both lockfile v1 and v2+.
    """
    v = lock.get("lockfileVersion")
    occ: List[Tuple[str, str, str]] = []
    if isinstance(v, int) and v >= 2:
        occ.extend(collect_occurrences_from_v2(lock))
        if not occ:
            occ.extend(collect_occurrences_from_v1(lock))
    else:
        occ.extend(collect_occurrences_from_v1(lock))
        if not occ:
            occ.extend(collect_occurrences_from_v2(lock))
    return occ


def find_matches(occurrences: Iterable[Tuple[str, str, str]],
                 targets: List[Tuple[str, str]]) -> List[Tuple[str, str, str]]:
    """
    Filter occurrences to only those matching exact package@version in targets.
    Returns list of (name, version, where).
    """
    target_set: Set[Tuple[str, str]] = set((n, v) for n, v in targets)
    return [(n, v, w) for (n, v, w) in occurrences if (n, v) in target_set]


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


def search_package_locks_in_repo(session: requests.Session, org: str, repo_full_name: str) -> List[dict]:
    """
    Search for package-lock.json files in a specific repository within the organization.
    """
    items = []
    page = 1
    while True:
        params = {
            "q": f"org:{org} repo:{repo_full_name} filename:package-lock.json",
            "per_page": 100,
            "page": page,
        }
        resp = http_get(session, f"{GITHUB_API}/search/code", params=params)
        if resp.status_code != 200:
            sys.stderr.write(f"Search API error: {resp.status_code} {resp.text}\n")
            break
        data = resp.json()
        page_items = data.get("items", [])
        # Filter to ensure only exact 'package-lock.json' files are processed
        page_items = [item for item in page_items if item.get("name") == "package-lock.json"]
        if not page_items:
            break
        items.extend(page_items)
        page += 1
    return items


def fetch_lock_content(session: requests.Session, item: dict) -> Optional[Tuple[str, dict]]:
    """
    Given a code search item, fetch the package-lock.json content.
    Returns (html_url, parsed_json) or None on errors.
    """
    contents_url = item.get("url")
    sha = item.get("sha")
    html_url = item.get("html_url")
    if not contents_url:
        repo = item.get("repository", {}).get("full_name")
        path = item.get("path")
        if not repo or not path:
            return None
        contents_url = f"{GITHUB_API}/repos/{repo}/contents/{path}"

    url = contents_url if "?" in contents_url else contents_url + (f"?ref={sha}" if sha else "")

    resp = http_get(session, url)
    if resp.status_code != 200:
        sys.stderr.write(f"Failed to fetch contents: {resp.status_code} {url}\n")
        return None

    payload = resp.json()
    if not isinstance(payload, dict):
        return None
    encoding = payload.get("encoding")
    content_b64 = payload.get("content")
    if encoding != "base64" or not content_b64:
        return None
    try:
        raw = base64.b64decode(content_b64).decode("utf-8", errors="replace")
        # Check if the file is a valid JSON
        if not raw.strip().startswith('{'):
            sys.stderr.write(f"File is not valid JSON: {html_url or url}\n")
            return None
        data = json.loads(raw)
        return html_url, data
    except Exception as e:
        sys.stderr.write(f"Error decoding/parsing JSON from {html_url or url}: {e}\n")
        return None


def make_markdown_report(
    org: str,
    targets: List[Tuple[str, str]],
    results: List[dict],
    total_files_scanned: int,
    unique_repos: Set[str],
) -> str:
    """
    Build the final Markdown report string.
    results entries: {
        'repo': 'owner/name',
        'path': 'path/to/package-lock.json',
        'html_url': 'https://github.com/.../package-lock.json',
        'lockfile_version': int|str|None,
        'matches': [ (name, version, where), ... ]
    }
    """
    targets_str = [f"{n}@{v}" for n, v in targets]
    occurrences_by_target: Dict[str, int] = {f"{n}@{v}": 0 for n, v in targets}
    for r in results:
        for (n, v, _w) in r["matches"]:
            occurrences_by_target[f"{n}@{v}"] = occurrences_by_target.get(f"{n}@{v}", 0) + 1

    lines: List[str] = []
    lines.append(f"# package-lock.json scan for org `{org}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Targets: {len(targets)} ({', '.join(targets_str)})")
    lines.append(f"- Repositories scanned (unique): {len(unique_repos)}")
    lines.append(f"- package-lock.json files scanned: {total_files_scanned}")
    lines.append(f"- Files with at least one match: {sum(1 for r in results if r['matches'])}")
    lines.append("")
    lines.append("### Target occurrence counts")
    lines.append("")
    lines.append("| Package@Version | Occurrences |")
    lines.append("|---|---|")
    for t in targets_str:
        lines.append(f"| `{t}` | {occurrences_by_target.get(t, 0)} |")
    lines.append("")

    lines.append("## Detailed matches")
    lines.append("")
    lines.append("| Repository | Path | Lockfile | Package | Version | Count in file | Example location | Link | Note |")
    lines.append("|---|---|---:|---|---|---:|---|---|---|")
    any_match = False
    for r in results:
        if not r["matches"] and "note" in r:
            lines.append(f"| `{r['repo']}` | `{r['path']}` | {r['lockfile_version'] if r['lockfile_version'] is not None else ''} "
                         f"|  |  |  |  | {r['note']} |")
            continue
        if not r["matches"]:
            continue
        any_match = True
        per_target: Dict[Tuple[str, str], List[str]] = {}
        for (n, v, w) in r["matches"]:
            per_target.setdefault((n, v), []).append(w)
        for (n, v), wheres in sorted(per_target.items()):
            count = len(wheres)
            example = wheres[0]
            lines.append(
                f"| `{r['repo']}` | `{r['path']}` | {r['lockfile_version'] if r['lockfile_version'] is not None else ''} "
                f"| `{n}` | `{v}` | {count} | `{example}` | [view]({r['html_url']}) |"
            )
    if not any_match:
        lines.append("_No matches found._")
    lines.append("")

    zeroes = [t for t, c in occurrences_by_target.items() if c == 0]
    if zeroes:
        lines.append("## Targets with zero occurrences")
        lines.append("")
        for t in zeroes:
            lines.append(f"- `{t}`")
        lines.append("")

    return "\n".join(lines)


def print_table(repo: str, data: List[Tuple[str, str, List[Tuple[str, str, str]]]], note: str = "") -> None:
    """
    Print a table of package occurrences for a specific repository.
    """
    print(f"\n## Repository: {repo}\n")
    if note:
        print(f"**Note:** {note}\n")
    print("| Package | Vulnerable Version | Found Versions | Repository |")
    print("|---|---|---|---|")
    for package, vuln_version, found_versions in data:
        found_versions_str = "<br>".join(f"{ver} ({loc})" for ver, loc, repo in found_versions)
        repo_names = ", ".join(set(repo for _, _, repo in found_versions))
        print(f"| {package} | {vuln_version} | {found_versions_str} | {repo_names} |")


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan GitHub org for package-lock.json and match target package versions.")
    parser.add_argument("--org", required=True, help="GitHub organization name (e.g., mattermost)")
    parser.add_argument("--versions", required=True, help="Path to versions.txt (format: name@version per line)")
    parser.add_argument("--max-pages", type=int, default=1000, help="Max search result pages (default: 1000)")
    parser.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds (default: 30)")
    parser.add_argument("--debug", action="store_true", help="Print debug info for target packages found at any version")
    parser.add_argument("--repo-type", choices=["public", "private", "all"], default="all",
                        help="Specify the type of repositories to scan: public, private, or all (default: all)")
    args = parser.parse_args()

    targets = parse_versions_file(args.versions)
    target_names: Set[str] = {name for name, _ in targets}
    token = get_token()

    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "gh-lock-scan/1.1",
    })
    # Note: requests.Session doesn't support a default timeout attribute; per-call timeouts not wired here.

    unique_repos: Set[str] = set()
    results: List[dict] = []
    total_files_scanned = 0

    repos = list_all_repositories(session, args.org, args.repo_type)
    total_repos = len(repos)
    for repo_idx, repo_full_name in enumerate(repos, start=1):
        items = search_package_locks_in_repo(session, args.org, repo_full_name)
        total_files = len(items)
        if total_files == 0:
            # Indicate that no package-lock.json file was found
            print_table(repo_full_name, [], "No package-lock.json file found")
            continue

        for idx, item in enumerate(items, start=1):
            repo_full = item.get("repository", {}).get("full_name", "")
            path = item.get("path", "")
            html_url = item.get("html_url", "")
            if repo_full:
                unique_repos.add(repo_full)

            fetched = fetch_lock_content(session, item)
            if not fetched:
                continue
            html_url, lock = fetched
            lockfile_version = lock.get("lockfileVersion", None)

            occurrences = collect_occurrences(lock)

            matches = find_matches(occurrences, targets)
            if not matches:
                # Indicate that no dependencies were matched
                print_table(repo_full, [], "No matching dependencies found")
            else:
                data_to_print = []
                found_by_name: Dict[str, List[Tuple[str, str, str]]] = {}
                for (n, v, w) in matches:
                    found_by_name.setdefault(n, []).append((v, w, repo_full))
                for name, lst in sorted(found_by_name.items()):
                    vuln_version = next((v for n, v in targets if n == name), "Unknown")
                    data_to_print.append((name, vuln_version, lst))
                print_table(repo_full, data_to_print)

            results.append({
                "repo": repo_full,
                "path": path,
                "html_url": html_url,
                "lockfile_version": lockfile_version,
                "matches": matches,
            })

            if idx % 25 == 0:
                sys.stderr.write(f"Scanned {idx}/{total_files} files in {repo_full_name}...\n")

        # Add a small delay between processing each repository
        time.sleep(3)

        # Update progress output to include current repository and overall progress
        sys.stderr.write(f"Processed {repo_idx}/{total_repos} repositories: {repo_full_name}\n")

    sys.stderr.write("Scanning complete. All files have been processed.\n")

    report_md = make_markdown_report(args.org, targets, results, total_files_scanned, unique_repos)
    print(report_md)


if __name__ == "__main__":
    main()