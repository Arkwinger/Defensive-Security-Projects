# Windows Event Log Analyzer

Simple Python utility that parses Windows Security logs and identifies:

- Failed logons (4625)
- New user creation (4720)
- Service creation (7045)
- Group membership changes

## Usage

python analyzer.py security.evtx
