# CertPatrol

<p align="center">
  <img width="609" height="250" alt="Torito Logo" src="https://torito.io/toritocertpatrol.png">
</p>

A fast, lightweight **Certificate Transparency (CT)** log tailer for your terminal. Filter domains with regex, run locally for privacy, and monitor in real time — no third-party servers, no tracking.  

A modern, local, privacy-friendly **CertStream** alternative.

> **Looking for a more advanced CertStream server alternative?**  
> Check out [Certstream Server Go](https://github.com/d-Rickyy-b/certstream-server-go) by [d-Rickyy-b](https://github.com/d-Rickyy-b) for a robust, production-grade solution.

---

## Installation

```bash
pip install certpatrol
```

---

## Quick start

```bash
# Find domains containing "example"
certpatrol --pattern "example"

# Find shop subdomains of amazon.com
certpatrol --pattern "shop.*\.amazon\.com$"

# Match against base domains only (e.g., example.co.uk)
certpatrol --pattern "argentina" --etld1
```

---

## Options

### Core Options
- `-p, --pattern PATTERN` – Regex pattern to match domains against (required)  
- `-l, --logs LOGS` – Specific CT logs to monitor (default: all usable logs)  
- `-v, --verbose` – Verbose output with extra info  
- `-h, --help` – Show help message and exit  

### Polling & Performance
- `-s, --poll-sleep SECONDS` – Initial poll interval (default: 3.0, adaptive)  
- `-mn, --min-poll-sleep` – Minimum poll sleep for adaptive polling (default: 1.0)  
- `-mx, --max-poll-sleep` – Maximum poll sleep for adaptive polling (default: 60.0)  
- `-b, --batch SIZE` – Batch size for fetching entries (default: 256)  
- `-m, --max-memory-mb` – Maximum memory usage in MB (default: 100)  

### Filtering & Output
- `-e, --etld1` – Match against base domains only (requires tldextract)  
- `-q, --quiet-warnings` – Suppress parse warnings (only show matches)  
- `-x, --quiet-parse-errors` – Suppress ASN.1 parsing warnings  
- `-d, --debug-all` – With -v, print detailed per-entry domain listings  

### Checkpoint Management
- `-c, --checkpoint-prefix` – Custom prefix for checkpoint files  
- `-k, --cleanup-checkpoints` – Clean up orphaned checkpoint files and exit  

---

## Examples

```bash
# Basic monitoring
certpatrol --pattern "petsdeli"

# Multiple patterns with verbose output
certpatrol --pattern "(petsdeli|pet-deli)" --verbose

# API subdomains with quiet mode
certpatrol --pattern "api.*\.google\.com$" --quiet-warnings

# All subdomains of a domain with custom memory limit
certpatrol --pattern ".*\.example\.com$" --max-memory-mb 200

# Base domain matching only
certpatrol --pattern "argentina" --etld1

# Run multiple instances with custom prefixes
certpatrol --pattern "domain1" --checkpoint-prefix "instance1" &
certpatrol --pattern "domain2" --checkpoint-prefix "instance2" &

# Clean up old checkpoint files
certpatrol --cleanup-checkpoints

# Performance tuning for high-volume monitoring
certpatrol --pattern "example" --batch 512 --min-poll-sleep 0.5 --max-poll-sleep 30

# Graceful shutdown examples
kill -TERM $(pgrep -f "certpatrol.*example")
# Or use Ctrl+C for immediate graceful shutdown
```

---

## Requirements

- Python 3.6+  
- requests  
- cryptography  
- idna  
- tldextract (optional, for --etld1)  
- psutil (optional, for memory monitoring)  

---

## Features

- **Real-time monitoring** – Starts from current time (no historical data)  
- **Graceful shutdown** – Handles SIGTERM, SIGINT, and SIGHUP signals properly  
- **Adaptive polling** – Automatically adjusts intervals based on activity and errors  
- **Memory management** – Monitors and limits memory usage to prevent excessive consumption  
- **Connection pooling** – Efficient HTTP session management with retry strategies  
- **Checkpoint persistence** – Automatic state saving with atomic writes  
- **Multi-instance support** – Unique checkpoint files per process with custom prefixes  

---

## Notes

- Checkpoints saved in `checkpoints/` folder with process-specific names  
- Signal handling ensures clean shutdown and checkpoint saving  
- Sleep periods are responsive to shutdown signals (checks every 0.5s)  
- Use Ctrl+C, `kill`, or system shutdown for graceful termination  

---

## License

MIT License — see [LICENSE](https://github.com/ToritoIO/CertPatrol/blob/main/LICENSE) file for details.