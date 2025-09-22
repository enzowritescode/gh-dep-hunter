# GitHub Dependency Hunter

This tool offers a solution for scanning `package-lock.json` and `go.sum` files to detect dependencies that may be associated with supply chain attacks, such as those seen in incidents like Shai Hulud.

## Prerequisites

- Python 3.9 or higher.
- `GH_TOKEN` or `GITHUB_TOKEN` is set in your environment.

## Setup

```
git clone https://github.com/enzowritescode/gh-dep-hunter.git

cd gh-dep-hunter

# (optional) create python virtual env
python3 -m venv venv
source venv/bin/activate

# install dependencies
pip install -r requirements.txt
```

## Usage

```
usage: dh.py [-h] --detector {npm,go} --org ORG --versions VERSIONS [--debug] [--repo-type {public,private}]

Scan GitHub org for dependencies and match target package versions.

options:
  -h, --help            show this help message and exit
  --detector {npm,go}   Specify the type of detector to use: npm or go
  --org ORG             GitHub organization name (e.g., mattermost)
  --versions VERSIONS   Path to versions.txt (format: name@version per line)
  --debug               Print debug info for target packages found at any version
  --repo-type {public,private}
                        Specify the type of repositories to scan: public or private (default: all)
```

## Examples

```
# run for all repos
python dh.py --detector npm --org YOUR_ORG --versions versions.txt > report.md
python dh.py --detector go --org YOUR_ORG --versions versions.txt > report.md

# run separate scans for public/private repos
python dh.py --detector npm --org YOUR_ORG --repo-type public --versions versions.txt > public_report.md
python dh.py --detector npm --org YOUR_ORG --repo-type private --versions versions.txt > private_report.md
python dh.py --detector go --org YOUR_ORG --repo-type public --versions versions.txt > public_report.md
python dh.py --detector go --org YOUR_ORG --repo-type private --versions versions.txt > private_report.md
```

## Sample versions files

Sample files to be used for the `--versions` flag are in `versions/`

- qix.txt
	- Impacted dependencies from the Qix npm account compromise

## Future Work

Support for other manifest files
