# CertPatrol

<p align="center">
  <img width="609" height="250" alt="Torito Logo" src="https://torito.io/toritocertpatrol.png">
</p>

A lightweight local Certificate Transparency (CT) log tailer that filters domains by regex patterns—intended as a local, privacy-friendly alternative to the now-defunct CertStream.

> **Looking for a more advanced CertStream server alternative?**  
> Check out [Certstream Server Go](https://github.com/d-Rickyy-b/certstream-server-go) by [d-Rickyy-b](https://github.com/d-Rickyy-b) for a robust, production-grade solution.

## What it does

Monitors CT logs in real-time and prints domains matching your regex pattern. Useful for:
- Domain monitoring
- Brand protection
- Security research
- Finding new subdomains

## Installation

```bash
pip install -r requirements.txt
```

## Quick start

```bash
# Find domains containing "example"
python certpatrol.py --pattern "example"

# Find shop subdomains of amazon.com
python certpatrol.py --pattern "shop.*\.amazon\.com$"

# Match against base domains only (e.g., example.co.uk)
python certpatrol.py --pattern "argentina" --etld1
```

## Options

- `-p, --pattern PATTERN` - Regex pattern to match (required)
- `-l, --logs LOGS` - Specific CT logs to monitor
- `-b, --batch SIZE` - Batch size for fetching (default: 256)
- `-s, --poll-sleep SECONDS` - Poll interval (default: 3.0)
- `-v, --verbose` - Show extra info
- `-e, --etld1` - Match base domains only
- `-k, --cleanup-checkpoints` - Clean up orphaned files

## Examples

```bash
# Basic monitoring
python certpatrol.py --pattern "petsdeli"

# Multiple patterns
python certpatrol.py --pattern "(petsdeli|pet-deli)" --verbose

# API subdomains
python certpatrol.py --pattern "api.*\.google\.com$"

# All subdomains of a domain
python certpatrol.py --pattern ".*\.example\.com$"

# Run multiple instances
python certpatrol.py --pattern "domain1" &
python certpatrol.py --pattern "domain2" &
```

## Requirements

- Python 3.6+
- requests
- cryptography
- idna
- tldextract (optional, for --etld1)

## Notes

- Starts monitoring from current time (no historical data)
- Checkpoints saved in `checkpoints/` folder
- Each process gets unique checkpoint file
- Use Ctrl+C to stop

## License

MIT License - see [LICENSE](LICENSE) file for details.
