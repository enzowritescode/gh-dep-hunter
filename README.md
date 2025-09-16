# GitHub Dependency Hunter

Scan `package-lock.json` files in your GitHub org for for specified package versions 

## Prerequisites

The script assumes you have a GitHub token in your environment, either `GH_TOKEN` or `GITHUB_TOKEN`

## Setup

```
git clone https://github.com/enzowritescode/gh-dep-hunter.git

cd dependency-finder

# create python virtual env
python3 -m venv venv
source venv/bin/activate
pip install requests
```

## Usage

```
# run for all repos
python dh.py --org YOUR_ORG --versions versions.txt > report.md

# run separate scans for public/private repos
python dh.py --org YOUR_ORG --repo-type public --versions versions.txt > public_report.md
python dh.py --org YOUR_ORG --repo-type private --versions versions.txt > private_report.md
```

## Sample versions files

Sample files to be used for the `--versions` flag are in `versions/`

- qix.txt
	- Impacted dependencies from the Qix npm account compromise

## Future Work

Support for other manifest files
