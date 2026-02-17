import json
import base64
import sys
import time
from typing import List, Tuple, Dict, Optional, Set
from config import GITHUB_API
from .base_detector import BaseDetector
from utils.github_utils import list_all_repositories, http_get
from utils.report_generator import print_table


class NpmDetector(BaseDetector):
    def __init__(self):
        self.search_delay = 2  # seconds between search requests
        self.content_delay = 0.1  # seconds between content fetches
        
    def search_files(self, session, org: str, repo_full_name: str) -> Tuple[List[dict], bool]:
        """
        Search for package-lock.json using two strategies:
        1. Code Search API (fast but may fail on large repos)
        2. Contents API fallback (slower but reliable)
        
        Returns: (items, has_package_json)
        """
        # Strategy 1: Try Code Search API first
        items = self._search_via_code_api(session, repo_full_name)
        
        if items:
            sys.stderr.write(f"[{repo_full_name}] Found {len(items)} package-lock.json file(s) via Code Search API\n")
            return items, False  # We don't know about package.json from Code Search
        
        # Strategy 2: Fallback to Contents API
        sys.stderr.write(f"[{repo_full_name}] Code Search returned 0 results, trying Contents API...\n")
        items, has_package_json = self._search_via_contents_api(session, repo_full_name)
        
        if items:
            sys.stderr.write(f"[{repo_full_name}] Found {len(items)} package-lock.json file(s) via Contents API\n")
        
        return items, has_package_json

    def _search_via_code_api(self, session, repo_full_name: str) -> List[dict]:
        """Search using Code Search API (may fail on large repos)"""
        items = []
        page = 1
        
        while True:
            params = {
                "q": f"repo:{repo_full_name} filename:package-lock.json",
                "per_page": 100,
                "page": page,
            }
            
            resp = http_get(session, f"{GITHUB_API}/search/code", params=params)
            
            if resp.status_code != 200:
                if resp.status_code == 404:
                    # Repository not found or not accessible
                    break
                sys.stderr.write(f"[{repo_full_name}] Search API error: {resp.status_code}\n")
                break
                
            data = resp.json()
            page_items = data.get("items", [])
            page_items = [item for item in page_items if item.get("name") == "package-lock.json"]
            
            if not page_items:
                break
                
            items.extend(page_items)
            page += 1
            
            if page_items:
                time.sleep(self.search_delay)
        
        return items

    def _search_via_contents_api(self, session, repo_full_name: str) -> Tuple[List[dict], bool]:
        """
        Fallback using Contents API.
        Search in common locations used by Mattermost repositories.
        
        Returns: (items, has_package_json)
        """
        items = []
        has_package_json = False
        
        # Common paths in Mattermost repositories
        common_paths = [
            "",                    # root
            "webapp",              
        ]
        
        not_found_count = 0
        
        for path in common_paths:
            # Check for package.json first
            package_json_path = f"{path}/package.json" if path else "package.json"
            package_json_url = f"{GITHUB_API}/repos/{repo_full_name}/contents/{package_json_path}"
            resp_pkg = http_get(session, package_json_url, suppress_404=True)
            
            if resp_pkg.status_code == 200:
                has_package_json = True
            
            # Then check for package-lock.json
            file_path = f"{path}/package-lock.json" if path else "package-lock.json"
            url = f"{GITHUB_API}/repos/{repo_full_name}/contents/{file_path}"
            
            resp = http_get(session, url, suppress_404=True)
            
            if resp.status_code == 200:
                data = resp.json()
                
                # Convert Contents API format to Search API format
                item = {
                    "name": "package-lock.json",
                    "path": file_path,
                    "sha": data.get("sha"),
                    "url": data.get("url"),
                    "html_url": data.get("html_url"),
                    "repository": {
                        "full_name": repo_full_name
                    }
                }
                items.append(item)
                sys.stderr.write(f"[{repo_full_name}] Found: {file_path}\n")
            elif resp.status_code == 404:
                not_found_count += 1
            else:
                # Log other errors
                sys.stderr.write(f"[{repo_full_name}] Unexpected error {resp.status_code} while checking {file_path}\n")
            
            time.sleep(self.content_delay)
        
        # Show summary message if nothing was found
        if not items and not_found_count > 0:
            if has_package_json:
                sys.stderr.write(f"[{repo_full_name}] ⚠️  Has package.json but no package-lock.json found\n")
            else:
                sys.stderr.write(f"[{repo_full_name}] Checked {len(common_paths)} common locations, no package-lock.json found\n")
        
        return items, has_package_json

    def fetch_content(self, session, item: dict) -> Optional[str]:
        """Fetch and decode the content of a file"""
        contents_url = item.get("url")
        sha = item.get("sha")
        repo_full_name = item.get("repository", {}).get("full_name", "unknown")
        path = item.get("path", "")
        
        if not contents_url:
            repo = item.get("repository", {}).get("full_name")
            if not repo or not path:
                return None
            contents_url = f"{GITHUB_API}/repos/{repo}/contents/{path}"

        url = contents_url if "?" in contents_url else contents_url + (f"?ref={sha}" if sha else "")

        resp = http_get(session, url)
        
        if resp.status_code != 200:
            sys.stderr.write(f"[{repo_full_name}] Failed to fetch {path}: HTTP {resp.status_code}\n")
            return None

        payload = resp.json()
        if not isinstance(payload, dict):
            return None
            
        encoding = payload.get("encoding")
        content_b64 = payload.get("content")
        
        if encoding != "base64" or not content_b64:
            sys.stderr.write(f"[{repo_full_name}] Invalid encoding for {path}\n")
            return None
            
        try:
            raw = base64.b64decode(content_b64).decode("utf-8", errors="replace")
            return raw
        except Exception as e:
            sys.stderr.write(f"[{repo_full_name}] Error decoding {path}: {e}\n")
            return None

    def parse_dependencies(self, content: str) -> List[Tuple[str, str, str]]:
        """Parse package-lock.json and extract dependencies"""
        try:
            lock = json.loads(content)
            return collect_occurrences(lock)
        except json.JSONDecodeError as e:
            sys.stderr.write(f"Error parsing package-lock.json: {e}\n")
            return []

    def find_matches(self, dependencies: List[Tuple[str, str, str]], targets: List[Tuple[str, str]]) -> List[Tuple[str, str, str]]:
        """Find dependencies matching target versions"""
        target_set: Set[Tuple[str, str]] = set((n, v) for n, v in targets)
        return [(n, v, w) for (n, v, w) in dependencies if (n, v) in target_set]

    def process_repositories(self, session, org: str, repo_type: str, targets: List[Tuple[str, str]], include_archived: bool = False) -> Tuple[Set[str], List[dict], int, List[str]]:
        """Process all repositories in the organization"""
        unique_repos: Set[str] = set()
        results: List[dict] = []
        total_files_scanned = 0
        repos_with_package_json_only: List[str] = []

        sys.stderr.write(f"\n{'='*80}\n")
        sys.stderr.write(f"Starting scan for organization: {org}\n")
        sys.stderr.write(f"Repository type: {repo_type}\n")
        sys.stderr.write(f"Target packages: {len(targets)}\n")
        sys.stderr.write(f"Include archived: {include_archived}\n")
        sys.stderr.write(f"{'='*80}\n\n")

        repos = list_all_repositories(session, org, repo_type, include_archived)
        total_repos = len(repos)
        
        sys.stderr.write(f"Found {total_repos} repositories to scan\n\n")
        
        for repo_idx, repo_full_name in enumerate(repos, start=1):
            sys.stderr.write(f"\n[{repo_idx}/{total_repos}] Processing: {repo_full_name}\n")
            
            items, has_package_json = self.search_files(session, org, repo_full_name)
            total_files = len(items)
            
            if total_files == 0:
                if has_package_json:
                    repos_with_package_json_only.append(repo_full_name)
                    print_table(repo_full_name, [], "⚠️  Has package.json but no package-lock.json")
                else:
                    print_table(repo_full_name, [], "No package-lock.json file found")
                continue

            sys.stderr.write(f"[{repo_full_name}] Analyzing {total_files} file(s)...\n")

            for idx, item in enumerate(items, start=1):
                repo_full = item.get("repository", {}).get("full_name", "")
                path = item.get("path", "")
                html_url = item.get("html_url", "")
                
                if repo_full:
                    unique_repos.add(repo_full)

                sys.stderr.write(f"[{repo_full_name}] Fetching: {path}\n")
                
                fetched = self.fetch_content(session, item)
                if not fetched:
                    continue

                dependencies = self.parse_dependencies(fetched)
                sys.stderr.write(f"[{repo_full_name}] Found {len(dependencies)} total dependencies in {path}\n")
                
                matches = self.find_matches(dependencies, targets)
                
                if matches:
                    sys.stderr.write(f"[{repo_full_name}] ⚠️  VULNERABLE: Found {len(matches)} matching vulnerable package(s) in {path}\n")
                else:
                    sys.stderr.write(f"[{repo_full_name}] ✓ No vulnerable packages found in {path}\n")

                results.append({
                    "repo": repo_full,
                    "path": path,
                    "html_url": html_url,
                    "matches": matches,
                })

                total_files_scanned += 1
                
                # Add small delay between content fetches
                time.sleep(self.content_delay)

            sys.stderr.write(f"[{repo_idx}/{total_repos}] Completed: {repo_full_name}\n")

        sys.stderr.write(f"\n{'='*80}\n")
        sys.stderr.write(f"Scan complete!\n")
        sys.stderr.write(f"Total repositories scanned: {total_repos}\n")
        sys.stderr.write(f"Total files analyzed: {total_files_scanned}\n")
        sys.stderr.write(f"Repositories with package-lock.json: {len(unique_repos)}\n")
        sys.stderr.write(f"Repositories with package.json only: {len(repos_with_package_json_only)}\n")
        sys.stderr.write(f"{'='*80}\n\n")
        
        return unique_repos, results, total_files_scanned, repos_with_package_json_only

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