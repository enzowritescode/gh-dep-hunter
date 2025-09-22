from typing import List, Tuple, Dict, Set


def make_markdown_report(
    org: str,
    targets: List[Tuple[str, str]],
    results: List[dict],
    total_files_scanned: int,
    unique_repos: Set[str],
    file_type: str
) -> str:
    """
    Build the final Markdown report string for dependencies.
    results entries: {
        'repo': 'owner/name',
        'path': 'path/to/file',
        'html_url': 'https://github.com/.../file',
        'matches': [ (name, version), ... ]
    }
    """
    targets_str = [f"{n}@{v}" for n, v in targets]
    occurrences_by_target: Dict[str, int] = {f"{n}@{v}": 0 for n, v in targets}
    for r in results:
        for (n, v) in r["matches"]:
            occurrences_by_target[f"{n}@{v}"] = occurrences_by_target.get(f"{n}@{v}", 0) + 1

    lines: List[str] = []
    lines.append(f"# {file_type} scan for org `{org}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Targets: {len(targets)} ({', '.join(targets_str)})")
    lines.append(f"- Repositories scanned (unique): {len(unique_repos)}")
    lines.append(f"- {file_type} files scanned: {total_files_scanned}")
    lines.append(f"- Files with at least one match: {sum(1 for r in results if r['matches'])}")
    lines.append("")
    lines.append("### Target occurrence counts")
    lines.append("")
    lines.append("| Name@Version | Occurrences |")
    lines.append("|---|---|")
    for t in targets_str:
        lines.append(f"| `{t}` | {occurrences_by_target.get(t, 0)} |")
    lines.append("")

    lines.append("## Detailed matches")
    lines.append("")
    lines.append("| Repository | Path | Name | Version | Count in file | Example location | Link | Note |")
    lines.append("|---|---|---:|---|---|---:|---|---|---|")
    any_match = False
    for r in results:
        if not r["matches"] and "note" in r:
            lines.append(f"| `{r['repo']}` | `{r['path']}` |  |  |  |  | {r['note']} |")
            continue
        if not r["matches"]:
            continue
        any_match = True
        per_target: Dict[Tuple[str, str], List[str]] = {}
        for (n, v) in r["matches"]:
            per_target.setdefault((n, v), []).append(r['path'])
        for (n, v), wheres in sorted(per_target.items()):
            count = len(wheres)
            example = wheres[0]
            lines.append(
                f"| `{r['repo']}` | `{r['path']}` | `{n}` | `{v}` | {count} | `{example}` | [view]({r['html_url']}) |"
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
