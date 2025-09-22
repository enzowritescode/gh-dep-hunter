import json
import base64
import requests
import sys
import time
from typing import List, Tuple, Dict, Optional, Set
from config import GITHUB_API
from utils.report_generator import make_markdown_report
from .base_detector import BaseDetector
from utils.github_utils import list_all_repositories
from utils.report_generator import print_table


class NpmDetector(BaseDetector):
    def search_files(self, session: requests.Session, org: str, repo_full_name: str) -> List[dict]:
        items = []
        page = 1
        while True:
            params = {
                "q": f"org:{org} repo:{repo_full_name} filename:package-lock.json",
                "per_page": 100,
                "page": page,
            }
            resp = session.get(f"{GITHUB_API}/search/code", params=params)
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

    def fetch_content(self, session: requests.Session, item: dict) -> Optional[str]:
        contents_url = item.get("url")
        sha = item.get("sha")
        if not contents_url:
            repo = item.get("repository", {}).get("full_name")
            path = item.get("path")
            if not repo or not path:
                return None
            contents_url = f"{GITHUB_API}/repos/{repo}/contents/{path}"

        url = contents_url if "?" in contents_url else contents_url + (f"?ref={sha}" if sha else "")

        resp = session.get(url)
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
            return raw
        except Exception as e:
            sys.stderr.write(f"Error decoding/parsing content from {url}: {e}\n")
            return None

    def parse_dependencies(self, content: str) -> List[Tuple[str, str]]:
        lock = json.loads(content)
        return collect_occurrences(lock)

    def find_matches(self, dependencies: List[Tuple[str, str]], targets: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        target_set: Set[Tuple[str, str]] = set((n, v) for n, v in targets)
        return [(n, v, w) for (n, v, w) in dependencies if (n, v) in target_set]

    def process_repositories(self, session: requests.Session, org: str, repo_type: str, targets: List[Tuple[str, str]]) -> Tuple[Set[str], List[dict], int]:
        unique_repos: Set[str] = set()
        results: List[dict] = []
        total_files_scanned = 0

        repos = list_all_repositories(session, org, repo_type)
        total_repos = len(repos)
        for repo_idx, repo_full_name in enumerate(repos, start=1):
            items = self.search_files(session, org, repo_full_name)
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

                fetched = self.fetch_content(session, item)
                if not fetched:
                    continue

                dependencies = self.parse_dependencies(fetched)
                matches = self.find_matches(dependencies, targets)

                results.append({
                    "repo": repo_full,
                    "path": path,
                    "html_url": html_url,
                    "matches": matches,
                })

                if idx % 25 == 0:
                    sys.stderr.write(f"Scanned {idx}/{total_files} files in {repo_full_name}...\n")

            # Add a small delay between processing each repository
            time.sleep(3)

            # Update progress output to include current repository and overall progress
            sys.stderr.write(f"Processed {repo_idx}/{total_repos} repositories: {repo_full_name}\n")

        sys.stderr.write("Scanning complete. All files have been processed.\n")

        return unique_repos, results, total_files_scanned

    @property
    def file_type(self) -> str:
        return "package-lock.json"


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


def find_matches(occurrences: List[Tuple[str, str, str]],
                 targets: List[Tuple[str, str]]) -> List[Tuple[str, str, str]]:
    """
    Filter occurrences to only those matching exact package@version in targets.
    Returns list of (name, version, where).
    """
    target_set: Set[Tuple[str, str]] = set((n, v) for n, v in targets)
    return [(n, v, w) for (n, v, w) in occurrences if (n, v) in target_set]


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
