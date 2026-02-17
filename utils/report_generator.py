from typing import List, Tuple, Dict, Set


from typing import List, Tuple, Dict, Set


def make_markdown_report(
    org: str,
    targets: List[Tuple[str, str]],
    results: List[dict],
    total_files_scanned: int,
    unique_repos: Set[str],
    file_type: str,
    repos_with_package_json_only: List[str] = []
) -> str:
    """
    Build the final Markdown report string for dependencies.
    """
    # Convert targets to string format for display
    targets_str = [f"{n}@{v}" for n, v in targets]
    
    # Count occurrences of each target
    occurrences_by_target: Dict[str, int] = {f"{n}@{v}": 0 for n, v in targets}
    
    for r in results:
        for match in r["matches"]:
            # Handle both tuple formats: (name, version) and (name, version, where)
            if len(match) >= 2:
                n, v = match[0], match[1]
                key = f"{n}@{v}"
                occurrences_by_target[key] = occurrences_by_target.get(key, 0) + 1

    # Start building the report
    lines: List[str] = []
    
    # Title
    lines.append(f"# {file_type} scan for org `{org}`")
    lines.append("")
    
    # Summary section
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Targets: {len(targets)} ({', '.join(targets_str)})")
    lines.append(f"- Repositories scanned (unique): {len(unique_repos)}")
    lines.append(f"- {file_type} files scanned: {total_files_scanned}")
    lines.append(f"- Files with at least one match: {sum(1 for r in results if r['matches'])}")
    
    # Add warning section for repos with package.json only (npm specific)
    if repos_with_package_json_only:
        lines.append(f"- ⚠️  Repositories with package.json but no package-lock.json: {len(repos_with_package_json_only)}")
    
    lines.append("")
    
    # Target occurrence counts table
    lines.append("### Target occurrence counts")
    lines.append("")
    lines.append("| Name@Version | Occurrences |")
    lines.append("|---|---|")
    for t in targets_str:
        count = occurrences_by_target.get(t, 0)
        lines.append(f"| `{t}` | {count} |")
    lines.append("")

    # Detailed matches section
    lines.append("## Detailed matches")
    lines.append("")
    lines.append("| Repository | Path | Name | Version | Count in file | Example location | Link |")
    lines.append("|---|---|---|---|---|---|---|")
    
    any_match = False
    for r in results:
        if not r["matches"]:
            continue
            
        any_match = True
        repo = r['repo']
        path = r['path']
        html_url = r['html_url']
        
        # Group matches by (name, version)
        per_target: Dict[Tuple[str, str], List[str]] = {}
        for match in r["matches"]:
            # Handle both tuple formats: (name, version, where) or (name, version)
            if len(match) >= 3:
                n, v, where = match[0], match[1], match[2]
            else:
                n, v = match[0], match[1]
                where = "(unknown)"
            per_target.setdefault((n, v), []).append(where)
        
        # Add a row for each unique (name, version) pair found in this file
        for (n, v), wheres in sorted(per_target.items()):
            count = len(wheres)
            example = wheres[0]
            lines.append(
                f"| `{repo}` | `{path}` | `{n}` | `{v}` | {count} | `{example}` | [view]({html_url}) |"
            )
    
    if not any_match:
        lines.append("| | | | | | | _No matches found._ |")
    lines.append("")

    # List targets with zero occurrences
    zeroes = [t for t, c in occurrences_by_target.items() if c == 0]
    if zeroes:
        lines.append("## Targets with zero occurrences")
        lines.append("")
        for t in zeroes:
            lines.append(f"- `{t}`")
        lines.append("")

    # Add section for repos with package.json but no lockfile (npm specific)
    if repos_with_package_json_only:
        lines.append("## ⚠️  Repositories with package.json but no package-lock.json")
        lines.append("")
        lines.append("These repositories contain Node.js projects but lack a lockfile. **Cannot verify exact dependency versions.**")
        lines.append("")
        lines.append("**Recommendation:** These repositories should be manually reviewed or developers should be asked to commit their package-lock.json files.")
        lines.append("")
        for repo in sorted(repos_with_package_json_only):
            lines.append(f"- `{repo}` - https://github.com/{repo}")
        lines.append("")

    return "\n".join(lines)


def print_table(repo: str, data: List[Tuple[str, str, List[Tuple[str, str, str]]]], note: str = "") -> None:
    """
    Print a table of package occurrences for a specific repository.
    """
    print(f"\n## Repository: {repo}\n")
    if note:
        print(f"**Note:** {note}\n")
    
    if not data:
        return
        
    print("| Package | Vulnerable Version | Found Versions | Repository |")
    print("|---|---|---|---|")
    for package, vuln_version, found_versions in data:
        found_versions_str = "<br>".join(f"{ver} ({loc})" for ver, loc, repo in found_versions)
        repo_names = ", ".join(set(repo for _, _, repo in found_versions))
        print(f"| {package} | {vuln_version} | {found_versions_str} | {repo_names} |")
