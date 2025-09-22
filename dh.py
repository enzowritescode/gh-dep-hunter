#!/usr/bin/env python3

import argparse
import base64
import json
import os
import sys
import time
from typing import Dict, List, Tuple, Set, Iterable, Optional

import requests

from detectors.npm_detector import NpmDetector
from detectors.go_detector import GoDetector
from config import GITHUB_API
from utils.github_utils import get_token, http_get, list_all_repositories
from utils.report_generator import make_markdown_report


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


def find_matches(occurrences: Iterable[Tuple[str, str, str]],
                 targets: List[Tuple[str, str]]) -> List[Tuple[str, str, str]]:
    """
    Filter occurrences to only those matching exact package@version in targets.
    Returns list of (name, version, where).
    """
    target_set: Set[Tuple[str, str]] = set((n, v) for n, v in targets)
    return [(n, v, w) for (n, v, w) in occurrences if (n, v) in target_set]


def add_common_flags(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--account", required=True, help="GitHub user or organization name")
    parser.add_argument("--versions", required=True, help="Path to versions.txt (format: name@version per line)")
    parser.add_argument("--debug", action="store_true", help="Print debug info for target packages found at any version")
    parser.add_argument("--repo-type", choices=["public", "private"], default="all", help="Specify the type of repositories to scan: public or private (default: all)")


def setup_session(token: str) -> requests.Session:
    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "gh-dep-hunter/1.0",
    })
    return session


def generate_report(org: str, targets: List[Tuple[str, str]], results: List[dict], total_files_scanned: int, unique_repos: Set[str]) -> None:
    sys.stderr.write("Scanning complete. All files have been processed.\n")
    report_md = make_markdown_report(org, targets, results, total_files_scanned, unique_repos)
    print(report_md)


def main() -> None:
    parser = argparse.ArgumentParser(description="Scan GitHub org for dependencies and match target package versions.")
    parser.add_argument('--detector', choices=['npm', 'go'], required=True, help='Specify the type of detector to use: npm or go')
    add_common_flags(parser)

    args = parser.parse_args()

    # Common setup
    targets = parse_versions_file(args.versions)
    token = get_token()
    session = setup_session(token)

    # Set the detector based on the --detector flag
    if args.detector == 'npm':
        detector = NpmDetector()
    elif args.detector == 'go':
        detector = GoDetector()
    else:
        sys.stderr.write(f"Error: Unknown detector '{args.detector}'\n")
        sys.exit(1)

    # Process repositories and generate report
    unique_repos, results, total_files_scanned = detector.process_repositories(session, args.account, args.repo_type, targets)
    report_md = make_markdown_report(args.account, targets, results, total_files_scanned, unique_repos, detector.file_type)
    print(report_md)


if __name__ == "__main__":
    main()