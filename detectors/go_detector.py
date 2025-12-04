# Placeholder for Go dependency detection logic

import re
import sys
import time
import base64
from typing import List, Tuple, Optional, Set, Dict
import requests
from config import GITHUB_API
from .base_detector import BaseDetector
from utils.github_utils import list_all_repositories, http_get
from utils.report_generator import print_table


class GoDetector(BaseDetector):
    def __init__(self):
        self.search_delay = 2  # seconds between search requests
        self.content_delay = 0.1  # seconds between content fetches

    def search_files(self, session: requests.Session, org: str, repo_full_name: str) -> List[dict]:
        """
        Search for go.sum using two strategies:
        1. Code Search API (fast but may fail on large repos)
        2. Contents API fallback (slower but reliable)
        """
        # Strategy 1: Try Code Search API first
        items = self._search_via_code_api(session, repo_full_name)
        
        if items:
            sys.stderr.write(f"[{repo_full_name}] Found {len(items)} go.sum file(s) via Code Search API\n")
            return items
        
        # Strategy 2: Fallback to Contents API
        sys.stderr.write(f"[{repo_full_name}] Code Search returned 0 results, trying Contents API...\n")
        items = self._search_via_contents_api(session, repo_full_name)
        
        if items:
            sys.stderr.write(f"[{repo_full_name}] Found {len(items)} go.sum file(s) via Contents API\n")
        
        return items

    def _search_via_code_api(self, session: requests.Session, repo_full_name: str) -> List[dict]:
        """Search using Code Search API (may fail on large repos)"""
        items = []
        page = 1
        
        while True:
            params = {
                "q": f"repo:{repo_full_name} filename:go.sum",
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
            page_items = [item for item in page_items if item.get("name") == "go.sum"]
            
            if not page_items:
                break
                
            items.extend(page_items)
            page += 1
            
            if page_items:
                time.sleep(self.search_delay)
        
        return items

    def _search_via_contents_api(self, session: requests.Session, repo_full_name: str) -> List[dict]:
        """
        Fallback using Contents API.
        Search in common locations used by Mattermost Go repositories.
        """
        items = []
        
        # Common paths in Mattermost Go repositories
        common_paths = [
            "",              # root (most Go projects)
            "server",        # mattermost/mattermost
            "cmd",           # command directories
            "api",           # API services
        ]
        
        not_found_count = 0
        
        for path in common_paths:
            file_path = f"{path}/go.sum" if path else "go.sum"
            url = f"{GITHUB_API}/repos/{repo_full_name}/contents/{file_path}"
            
            resp = http_get(session, url, suppress_404=True)
            
            if resp.status_code == 200:
                data = resp.json()
                
                # Convert Contents API format to Search API format
                item = {
                    "name": "go.sum",
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
            sys.stderr.write(f"[{repo_full_name}] Checked {len(common_paths)} common locations, no go.sum found\n")
        
        return items

    def fetch_content(self, session: requests.Session, item: dict) -> Optional[str]:
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

    def parse_dependencies(self, content: str) -> List[Tuple[str, str]]:
        """
        Parse the go.sum file content to extract module names and versions.
        Returns a list of tuples (module, version).
        """
        pattern = re.compile(r"^([^\s]+)\s+([^\s]+)\s+\w+$")
        dependencies = []
        
        for line in content.splitlines():
            match = pattern.match(line)
            if match:
                module, version = match.groups()
                dependencies.append((module, version))
                
        return dependencies

    def find_matches(self, dependencies: List[Tuple[str, str]], targets: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        """Find dependencies matching target versions"""
        target_set = set(targets)
        return [(module, version) for module, version in dependencies if (module, version) in target_set]

    def process_repositories(self, session: requests.Session, org: str, repo_type: str, targets: List[Tuple[str, str]], include_archived: bool = False) -> Tuple[Set[str], List[dict], int, List[str]]:  # NUEVO: parámetro
        """Process all repositories in the organization"""
        unique_repos: Set[str] = set()
        results: List[dict] = []
        total_files_scanned = 0

        sys.stderr.write(f"\n{'='*80}\n")
        sys.stderr.write(f"Starting scan for organization: {org}\n")
        sys.stderr.write(f"Repository type: {repo_type}\n")
        sys.stderr.write(f"Target modules: {len(targets)}\n")
        sys.stderr.write(f"Include archived: {include_archived}\n")  # NUEVO: log
        sys.stderr.write(f"{'='*80}\n\n")

        repos = list_all_repositories(session, org, repo_type, include_archived)  # NUEVO: pasar parámetro
        total_repos = len(repos)
        
        sys.stderr.write(f"Found {total_repos} repositories to scan\n\n")

        for repo_idx, repo_full_name in enumerate(repos, start=1):
            sys.stderr.write(f"\n[{repo_idx}/{total_repos}] Processing: {repo_full_name}\n")
            
            items = self.search_files(session, org, repo_full_name)
            total_files = len(items)
            
            if total_files == 0:
                print_table(repo_full_name, [], "No go.sum file found")
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
                    sys.stderr.write(f"[{repo_full_name}] ⚠️  VULNERABLE: Found {len(matches)} matching vulnerable module(s) in {path}\n")
                else:
                    sys.stderr.write(f"[{repo_full_name}] ✓ No vulnerable modules found in {path}\n")

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
        sys.stderr.write(f"Repositories with go.sum: {len(unique_repos)}\n")
        sys.stderr.write(f"{'='*80}\n\n")

        return unique_repos, results, total_files_scanned

    @property
    def file_type(self) -> str:
        return "go.sum"