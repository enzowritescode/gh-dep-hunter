# Placeholder for Go dependency detection logic

from typing import List, Tuple, Optional, Set, Dict
import re
import requests
import sys
from config import GITHUB_API
import base64
import time
from utils.report_generator import make_markdown_report, print_table
from utils.github_utils import list_all_repositories
from .base_detector import BaseDetector


def parse_go_sum(go_sum_content: str) -> List[Tuple[str, str]]:
    """
    Parse the go.sum file content to extract module names and versions.
    Returns a list of tuples (module, version).
    """
    pattern = re.compile(r"^([^\s]+)\s+([^\s]+)\s+\w+$")
    dependencies = []
    for line in go_sum_content.splitlines():
        match = pattern.match(line)
        if match:
            module, version = match.groups()
            dependencies.append((module, version))
    return dependencies


class GoDetector(BaseDetector):
    def search_files(self, session: requests.Session, org: str, repo_full_name: str) -> List[dict]:
        items = []
        page = 1
        while True:
            params = {
                "q": f"org:{org} repo:{repo_full_name} filename:go.sum",
                "per_page": 100,
                "page": page,
            }
            resp = session.get(f"{GITHUB_API}/search/code", params=params)
            if resp.status_code != 200:
                sys.stderr.write(f"Search API error: {resp.status_code} {resp.text}\n")
                break
            data = resp.json()
            page_items = data.get("items", [])
            # Filter to ensure only exact 'go.sum' files are processed
            page_items = [item for item in page_items if item.get("name") == "go.sum"]
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
        return parse_go_sum(content)

    def find_matches(self, dependencies: List[Tuple[str, str]], targets: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
        target_set = set(targets)
        return [(module, version) for module, version in dependencies if (module, version) in target_set]

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
                # Indicate that no go.sum file was found
                print_table(repo_full_name, [], "No go.sum file found")
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
        return "go.sum"
