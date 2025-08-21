#!/usr/bin/env python3
"""
Torito CertPatrol - Tiny local CT tailer that filters domains by a regex pattern.

Author: Martin Aberastegue
Website: https://torito.io
Repository: https://github.com/ToritoIO/CertPatrol

Options:
  -p, --pattern PATTERN     Regex pattern to match domains against (required)
  -l, --logs LOGS           CT logs to tail (default: fetch all usable logs)
  -b, --batch SIZE          Batch size for fetching entries (default: 256)
  -s, --poll-sleep SECONDS  Seconds to sleep between polls (default: 3.0)
  -v, --verbose             Verbose output (extra info for matches)
  -q, --quiet-warnings      Suppress parse warnings (only show actual matches)
  -e, --etld1               Match against registrable base domain instead of full domain
  -d, --debug-all           With -v, print per-batch and per-entry domain listings
  -x, --quiet-parse-errors  Suppress ASN.1 parsing warnings (common in CT logs)
  -c, --checkpoint-prefix   Custom prefix for checkpoint file (useful for multiple instances)
  -k, --cleanup-checkpoints Clean up orphaned checkpoint files and exit
  -h, --help                Show this help message and exit

Usage Examples:
  # Basic domain matching
  python certpatrol.py --pattern 'petsdeli'        # prints matching domains
  python certpatrol.py --pattern '(petsdeli|pet-deli)' --verbose
  
  # Search for specific words in subdomains of specific domains
  python certpatrol.py --pattern 'shop'            # finds domains containing "shop"
  python certpatrol.py --pattern 'shop.*\.amazon\.com$'  # shop subdomains of amazon.com
  python certpatrol.py --pattern 'api.*\.google\.com$'   # API subdomains of google.com
  python certpatrol.py --pattern '.*\.example\.com$'     # all subdomains of example.com
  
  # Match only against the registrable base domain (eTLD+1), e.g. example.co.uk
  python certpatrol.py --pattern 'argentina' --etld1 --verbose
  
  # Show full debug (list all domains per entry): add --debug-all
  python certpatrol.py --pattern 'argentina' -v --debug-all
  
  # Suppress parsing warnings and errors for cleaner output
  python certpatrol.py --pattern 'argentina' --quiet-parse-errors
  
  # Run multiple instances in parallel (each gets unique checkpoint file)
  python certpatrol.py --pattern 'domain1' --checkpoint-prefix 'instance1' &
  python certpatrol.py --pattern 'domain2' --checkpoint-prefix 'instance2' &
  
  # Or let them auto-generate unique names (default behavior)
  python certpatrol.py --pattern 'domain1' &
  python certpatrol.py --pattern 'domain2' &
  
  # Clean up orphaned checkpoint files
  python certpatrol.py --cleanup-checkpoints

Requirements:
  pip install requests cryptography idna
  # Optional but recommended for --etld1
  pip install tldextract

Notes:
- Tails from "now" (no historical backfill). If you want history, lower the checkpoint.
- Checkpoints are stored in checkpoints/ folder next to this script.
"""

# Suppress OpenSSL warnings BEFORE any imports
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="urllib3")
warnings.filterwarnings("ignore", message=".*OpenSSL.*")
warnings.filterwarnings("ignore", message=".*LibreSSL.*")

# Try to suppress specific urllib3 warnings
try:
    from urllib3.exceptions import NotOpenSSLWarning
    warnings.filterwarnings("ignore", category=NotOpenSSLWarning)
except ImportError:
    pass

import argparse
import json
import os
import re
import time
import multiprocessing
from typing import List, Tuple, Optional

import idna
import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# Make checkpoint file unique per process to avoid conflicts when running multiple instances
CHECKPOINT_DIR = "checkpoints"
CHECKPOINT_FILE = os.path.join(CHECKPOINT_DIR, f"certpatrol_checkpoints_{os.getpid()}.json")
USER_AGENT = "torito-certpatrol/1.0 (+local)"
LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

# Dynamic CT log discovery - fetched from Google's official list
CT_LOGS = {}

# --- TLS vector helpers (RFC 6962 extra_data uses TLS Certificate structure encoding) ---

def _read_uint24(b: bytes, offset: int) -> Tuple[int, int]:
    """Read a 3-byte big-endian unsigned int, return (value, new_offset)."""
    if offset + 3 > len(b):
        raise ValueError("Truncated uint24")
    return (b[offset] << 16) | (b[offset+1] << 8) | b[offset+2], offset + 3

def parse_tls_cert_chain(extra_data_b64: str) -> List[bytes]:
    """
    Parse certificates from CT 'extra_data' (base64).
    CT logs concatenate DER certificates directly, not in TLS structure.
    Returns a list of DER cert bytes [leaf, intermediates...].
    """
    import base64
    try:
        raw = base64.b64decode(extra_data_b64)
        if len(raw) < 2:
            return []
            
        # Look for certificate boundaries by finding SEQUENCE tags (0x30)
        certs = []
        pos = 0
        
        while pos < len(raw):
            if pos + 2 >= len(raw):
                break
                
            if raw[pos] == 0x30:  # SEQUENCE
                # Read the length
                if raw[pos + 1] & 0x80:  # Long form length
                    if raw[pos + 1] == 0x82:  # 2-byte length
                        if pos + 4 <= len(raw):
                            length = (raw[pos + 2] << 8) | raw[pos + 3]
                            
                            if pos + 4 + length <= len(raw):
                                cert_data = raw[pos:pos + 4 + length]
                                certs.append(cert_data)
                                pos += 4 + length
                            else:
                                break
                        else:
                            break
                    else:
                        # Unsupported long form length
                        break
                else:  # Short form length
                    length = raw[pos + 1]
                    
                    if pos + 2 + length <= len(raw):
                        cert_data = raw[pos:pos + 2 + length]
                        certs.append(cert_data)
                        pos += 2 + length
                    else:
                        break
            else:
                pos += 1
                
        return certs
        
    except Exception:
        return []

def extract_domains_from_der(der_bytes: bytes) -> List[str]:
    """
    Extract DNS names from SAN; if absent, fallback to CN when it looks like a DNS name.
    Returns lowercased, Unicode (IDNA-decoded) domains.
    """
    domains = []
    cert = x509.load_der_x509_certificate(der_bytes)
    # Try SAN first
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        for name in san.value.get_values_for_type(x509.DNSName):
            domains.append(name)
    except x509.ExtensionNotFound:
        pass

    # Fallback: subject CN
    if not domains:
        try:
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            # crude DNS-ish check: contains a dot or wildcard
            if "." in cn or cn.startswith("*."):
                domains.append(cn)
        except IndexError:
            pass

    # Normalize: lower-case, IDNA decode to Unicode for display, but keep ASCII if decode fails
    normed = []
    for d in domains:
        d = d.strip().lower()
        if d.startswith("*."):
            base = d[2:]
            try:
                u = idna.decode(base)
                normed.append("*." + u)
            except Exception:
                normed.append(d)
        else:
            try:
                u = idna.decode(d)
                normed.append(u)
            except Exception:
                normed.append(d)
    return list(dict.fromkeys(normed))  # dedupe, keep order

def registrable_domain(domain: str) -> str:
    """
    Return the registrable base domain (eTLD+1) for a given domain string.
    Falls back to a best-effort heuristic if tldextract is unavailable.
    Keeps Unicode/IDNA-decoded input as-is.
    """
    # Strip wildcard for matching purposes
    d = domain.lstrip("*.")
    try:
        # Import locally to avoid hard dependency unless used
        import tldextract  # type: ignore
        ext = tldextract.extract(d)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return d
    except Exception:
        parts = d.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return d

# --- Dynamic CT log discovery ---

def fetch_usable_ct_logs(verbose: bool = False) -> dict:
    """
    Fetch the current list of usable CT logs from Google's official list.
    Returns a dict mapping log names to base URLs.
    """
    try:
        if verbose:
            print("[info] Fetching current CT log list from Google...")
        
        resp = requests.get(LOG_LIST_URL, headers={"User-Agent": USER_AGENT}, timeout=10)
        resp.raise_for_status()
        data = resp.json()
        
        usable_logs = {}
        
        # Extract logs from all operators
        for operator in data.get("operators", []):
            operator_name = operator.get("name", "unknown")
            
            for log in operator.get("logs", []):
                # Check if log is usable/qualified
                state = log.get("state", {})
                if "usable" in state or "qualified" in state:
                    url = log["url"].rstrip("/")
                    description = log.get("description", "")
                    
                    # Create a simple name from description or URL
                    if description:
                        # Extract meaningful name from description
                        name = description.lower()
                        name = name.replace("'", "").replace('"', "")
                        name = name.replace(" log", "").replace(" ", "_")
                        # Take first part if too long
                        name = name.split("_")[0:2]
                        name = "_".join(name)
                    else:
                        # Fallback to URL-based name
                        name = url.split("/")[-1] or url.split("/")[-2]
                    
                    # Ensure unique names
                    original_name = name
                    counter = 1
                    while name in usable_logs:
                        name = f"{original_name}_{counter}"
                        counter += 1
                    
                    usable_logs[name] = url
                    
                    if verbose:
                        print(f"[info] Found usable log: {name} -> {url}")
        
        if verbose:
            print(f"[info] Found {len(usable_logs)} usable CT logs")
        
        return usable_logs
        
    except Exception as e:
        if verbose:
            print(f"[warn] Failed to fetch CT log list: {e}")
        # Fallback to a known working log
        return {"xenon2023": "https://ct.googleapis.com/logs/xenon2023"}

def save_debug_response(name: str, entry: dict, absolute_idx: int) -> None:
    """
    Save a CT log entry to a debug file for analysis.
    """
    debug_dir = "debug_responses"
    if not os.path.exists(debug_dir):
        os.makedirs(debug_dir)
    
    filename = f"{debug_dir}/{name}_{absolute_idx}.json"
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(entry, f, indent=2, default=str)
        print(f"[debug] Saved response to {filename}")
    except Exception as e:
        print(f"[debug] Failed to save response: {e}")

# --- CT polling ---

def get_sth(base_url: str) -> int:
    """Return current tree_size of the CT log."""
    r = requests.get(f"{base_url}/ct/v1/get-sth", headers={"User-Agent": USER_AGENT}, timeout=20)
    r.raise_for_status()
    data = r.json()
    return int(data["tree_size"])

def get_entries(base_url: str, start: int, end: int) -> List[dict]:
    """Fetch entries [start..end] inclusive (may return fewer)."""
    r = requests.get(
        f"{base_url}/ct/v1/get-entries",
        params={"start": start, "end": end},
        headers={"User-Agent": USER_AGENT},
        timeout=30,
    )
    r.raise_for_status()
    return r.json().get("entries", [])

def ensure_checkpoint_dir():
    """Ensure the checkpoints directory exists."""
    if not os.path.exists(CHECKPOINT_DIR):
        os.makedirs(CHECKPOINT_DIR)

def load_checkpoints() -> dict:
    ensure_checkpoint_dir()
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (json.JSONDecodeError, IOError) as e:
            # If checkpoint file is corrupted, start fresh
            print(f"[warn] Corrupted checkpoint file, starting fresh: {e}")
            return {}
    return {}

def save_checkpoints(cp: dict) -> None:
    """Save checkpoints with atomic write to avoid corruption."""
    tmp = CHECKPOINT_FILE + ".tmp"
    max_retries = 3
    retry_delay = 0.1
    
    for attempt in range(max_retries):
        try:
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(cp, fh, indent=2)
            os.replace(tmp, CHECKPOINT_FILE)
            return
        except (OSError, IOError) as e:
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
                continue
            else:
                # If save fails, try to clean up temp file
                try:
                    if os.path.exists(tmp):
                        os.unlink(tmp)
                except:
                    pass
                raise e

def cleanup_checkpoint_file():
    """Clean up checkpoint file when process exits."""
    try:
        if os.path.exists(CHECKPOINT_FILE):
            os.unlink(CHECKPOINT_FILE)
    except:
        pass

def cleanup_orphaned_checkpoints():
    """Clean up checkpoint files from processes that are no longer running."""
    import glob
    ensure_checkpoint_dir()
    checkpoint_files = glob.glob(os.path.join(CHECKPOINT_DIR, "*.json"))
    cleaned = 0
    
    for checkpoint_file in checkpoint_files:
        try:
            # Extract filename without path
            filename = os.path.basename(checkpoint_file)
            # Try to parse the filename to extract PID
            if filename.startswith("certpatrol_checkpoints_") and filename.endswith(".json"):
                pid_part = filename[24:-5]  # Remove "certpatrol_checkpoints_" prefix and ".json" suffix
                if "_" in pid_part:
                    # Has custom prefix, extract PID from end
                    pid = pid_part.split("_")[-1]
                else:
                    # No custom prefix, entire part is PID
                    pid = pid_part
                
                try:
                    pid = int(pid)
                    # Check if process is still running
                    os.kill(pid, 0)
                    # Process exists, keep file
                except (ValueError, OSError):
                    # Process doesn't exist, remove file
                    os.unlink(checkpoint_file)
                    cleaned += 1
                    print(f"[cleanup] Removed orphaned checkpoint: {filename}")
        except Exception as e:
            print(f"[warn] Failed to process checkpoint file {checkpoint_file}: {e}")
    
    if cleaned > 0:
        print(f"[cleanup] Cleaned up {cleaned} orphaned checkpoint files")
    else:
        print("[cleanup] No orphaned checkpoint files found")

def tail_logs(
    logs: List[str],
    pattern: re.Pattern,
    batch: int = 256,
    poll_sleep: float = 3.0,
    verbose: bool = False,
    ct_logs: dict = None,
    quiet_warnings: bool = False,
    match_scope: str = "full",
    debug_all: bool = False,
    quiet_parse_errors: bool = False,
):
    if ct_logs is None:
        ct_logs = CT_LOGS
    
    checkpoints = load_checkpoints()

    # Initialize checkpoints at current tree_size (tail-from-now semantics)
    for name in logs:
        if name not in ct_logs:
            if verbose:
                print(f"[warn] Unknown log: {name}")
            continue
        base = ct_logs[name]
        if name not in checkpoints:
            try:
                tree_size = get_sth(base)
                checkpoints[name] = tree_size  # next index to fetch
                if verbose:
                    print(f"[init] {name}: starting at index {tree_size}")
            except Exception as e:
                print(f"[warn] {name}: failed to init STH ({e})")
                checkpoints[name] = 0

    save_checkpoints(checkpoints)

    while True:
        any_progress = False
        for name in logs:
            if name not in ct_logs:
                continue
            base = ct_logs[name]
            # Determine target size
            try:
                tree_size = get_sth(base)
            except Exception as e:
                if verbose:
                    print(f"[warn] {name}: get-sth failed: {e}")
                continue

            next_idx = checkpoints.get(name, 0)
            if next_idx >= tree_size:
                # nothing new
                continue

            any_progress = True
            # Fetch in batches up to current tree_size-1
            end_idx = min(next_idx + batch - 1, tree_size - 1)

            try:
                entries = get_entries(base, next_idx, end_idx)
            except Exception as e:
                if verbose:
                    print(f"[warn] {name}: get-entries {next_idx}-{end_idx} failed: {e}")
                continue

            # Process entries
            if verbose and debug_all and entries:
                print(f"[debug] {name}: processing {len(entries)} entries from {next_idx} to {end_idx}")
                
            for i, entry in enumerate(entries):
                absolute_idx = next_idx + i
                try:
                    chain = parse_tls_cert_chain(entry["extra_data"])
                    if not chain:
                        if verbose:
                            print(f"[debug] {name}@{absolute_idx}: no valid chain parsed")
                            # Save first few failed responses for debugging
                            if absolute_idx % 100 == 0:  # Save every 100th failed entry
                                save_debug_response(name, entry, absolute_idx)
                        continue
                    leaf_der = chain[0]  # end-entity first
                    domains = extract_domains_from_der(leaf_der)
                    
                    if verbose and debug_all and domains:
                        print(f"[debug] {name}@{absolute_idx}: found domains: {domains}")
                        
                except Exception as e:
                    if verbose and not quiet_warnings and not quiet_parse_errors:
                        print(f"[warn] {name}@{absolute_idx}: parse failed: {e}")
                        # Save first few failed responses for debugging
                        if absolute_idx % 100 == 0:  # Save every 100th failed entry
                            save_debug_response(name, entry, absolute_idx)
                    continue

                # Print matches (one per domain line to mimic your grep output)
                for d in domains:
                    target = d.lstrip("*.") if match_scope == "full" else registrable_domain(d)
                    if pattern.search(target):
                        print(d, flush=True)  # keep it simple and pipe-friendly
                        # If you want richer output, gate it behind verbose:
                        if verbose:
                            ts = entry.get("sct", {}).get("timestamp")  # not in v1 payloads typically
                            print(f"# matched {d} | log={name} idx={absolute_idx} ts={ts}", flush=True)

            checkpoints[name] = end_idx + 1
            save_checkpoints(checkpoints)

        if not any_progress:
            time.sleep(poll_sleep)

def main():
    parser = argparse.ArgumentParser(
        description="Torito CertPatrol - Tiny local CT tailer that filters domains by a regex pattern",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )
    parser.add_argument(
        "--pattern", "-p",
        required=False,  # Make optional since cleanup-checkpoints doesn't need it
        help="Regex pattern to match domains against"
    )
    parser.add_argument(
        "--logs", "-l",
        nargs="+",
        default=None,
        help="CT logs to tail (default: fetch all usable logs)"
    )
    parser.add_argument(
        "--batch", "-b",
        type=int,
        default=256,
        help="Batch size for fetching entries (default: 256)"
    )
    parser.add_argument(
        "--poll-sleep", "-s",
        type=float,
        default=3.0,
        help="Seconds to sleep between polls (default: 3.0)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose output"
    )
    parser.add_argument(
        "--quiet-warnings", "-q",
        action="store_true",
        help="Suppress parse warnings (only show actual matches)"
    )
    parser.add_argument(
        "--etld1", "-e",
        action="store_true",
        help="Match against registrable base domain instead of full domain"
    )
    parser.add_argument(
        "--debug-all", "-d",
        action="store_true",
        help="With -v, print per-batch and per-entry domain listings"
    )
    parser.add_argument(
        "--quiet-parse-errors", "-x",
        action="store_true",
        help="Suppress ASN.1 parsing warnings (common in CT logs)"
    )
    parser.add_argument(
        "--checkpoint-prefix", "-c",
        help="Custom prefix for checkpoint file (useful for multiple instances)"
    )
    parser.add_argument(
        "--cleanup-checkpoints", "-k",
        action="store_true",
        help="Clean up orphaned checkpoint files and exit"
    )
    parser.add_argument(
        "--help", "-h",
        action="store_true",
        help="Show this help message and exit"
    )

    args = parser.parse_args()
    
    # Handle help command
    if args.help:
        print(__doc__)
        return 0
    
    # Handle cleanup command
    if args.cleanup_checkpoints:
        cleanup_orphaned_checkpoints()
        return 0
    
    # Validate that pattern is provided for normal operation
    if not args.pattern:
        print("Error: --pattern/-p is required (unless using --cleanup-checkpoints)")
        return 1
    
    # Set checkpoint file with custom prefix if provided
    global CHECKPOINT_FILE
    if args.checkpoint_prefix:
        CHECKPOINT_FILE = os.path.join(CHECKPOINT_DIR, f"certpatrol_checkpoints_{args.checkpoint_prefix}_{os.getpid()}.json")
    
    # Register cleanup function to remove checkpoint file on exit
    import atexit
    atexit.register(cleanup_checkpoint_file)
    
    try:
        pattern = re.compile(args.pattern, re.IGNORECASE)
    except re.error as e:
        print(f"Invalid regex pattern: {e}")
        return 1

    # Fetch current usable CT logs
    ct_logs = fetch_usable_ct_logs(verbose=args.verbose)
    if not ct_logs:
        print("No usable CT logs found")
        return 1

    # Use specified logs or default to all usable logs
    if args.logs is None:
        logs_to_use = list(ct_logs.keys())
    else:
        logs_to_use = args.logs
        # Validate log names
        invalid_logs = [name for name in logs_to_use if name not in ct_logs]
        if invalid_logs:
            print(f"Unknown log(s): {', '.join(invalid_logs)}")
            print(f"Available logs: {', '.join(sorted(ct_logs.keys()))}")
            return 1

    if args.verbose:
        print(f"Tailing logs: {', '.join(logs_to_use)}")
        print(f"Pattern: {args.pattern}")
        print(f"Batch size: {args.batch}")
        print(f"Poll sleep: {args.poll_sleep}s")
        print("---")

    try:
        tail_logs(
            logs=logs_to_use,
            pattern=pattern,
            batch=args.batch,
            poll_sleep=args.poll_sleep,
            verbose=args.verbose,
            ct_logs=ct_logs,
            quiet_warnings=args.quiet_warnings,
            match_scope="etld1" if args.etld1 else "full",
            debug_all=args.debug_all,
            quiet_parse_errors=args.quiet_parse_errors
        )
    except KeyboardInterrupt:
        if args.verbose:
            print("\nInterrupted by user")
        return 0
    except Exception as e:
        print(f"Error: {e}")
        return 1

if __name__ == "__main__":
    exit(main())
