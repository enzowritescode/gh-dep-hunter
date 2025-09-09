# Dependency Finder

## Prerequisites

The script assumes you have a GitHub token in your environment, either `GH_TOKEN` or `GITHUB_TOKEN`

## Setup

```
git clone https://github.com/enzowritescode/dependency-finder.git

cd dependency-finder

# create python virtual env
python3 -m venv venv
source venv/bin/activate
pip install requests
```

## Usage

```
# run for all repos
python df.py --org YOUR_ORG --versions versions.txt > report.md 

# run separate scans for public/private repos
python df.py --org YOUR_ORG --repo-type public --versions versions.txt > public_report.md 
python df.py --org YOUR_ORG --repo-type private --versions versions.txt > private_report.md
```

## Sample versions files

Sample files to be used for the `--versions` flag are in `versions/`

- qix.txt
	- Impacted dependencies from the Qix npm account compromise
