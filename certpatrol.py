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
  -m, --max-memory-mb       Maximum memory usage in MB for batch processing (default: 100)
  -mn, --min-poll-sleep     Minimum poll sleep time for adaptive polling (default: 1.0)
  -mx, --max-poll-sleep     Maximum poll sleep time for adaptive polling (default: 60.0)
  -h, --help                Show this help message and exit

Requirements:
  pip install requests cryptography idna
  # Optional but recommended for --etld1
  pip install tldextract
"""

# Suppress OpenSSL and cryptography warnings BEFORE any imports
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="urllib3")
warnings.filterwarnings("ignore", message=".*OpenSSL.*")
warnings.filterwarnings("ignore", message=".*LibreSSL.*")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="cryptography")
warnings.filterwarnings("ignore", message=".*serial number.*")

try:
    from urllib3.exceptions import NotOpenSSLWarning
    warnings.filterwarnings("ignore", category=NotOpenSSLWarning)
except ImportError:
    pass

import argparse
import json
import logging
import os
import re
import signal
import sys
import time
import multiprocessing
import gc
from typing import List, Tuple, Optional, Dict, Any, Iterator, Union
from contextlib import contextmanager

import idna
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from cryptography import x509
from cryptography.hazmat.primitives import serialization

# Make checkpoint file unique per process to avoid conflicts when running multiple instances
CHECKPOINT_DIR = "checkpoints"
CHECKPOINT_FILE = os.path.join(CHECKPOINT_DIR, f"certpatrol_checkpoints_{os.getpid()}.json")
USER_AGENT = "torito-certpatrol/1.2.0 (+local)"
LOG_LIST_URL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

# Phase 2: Connection pooling and rate limiting constants
DEFAULT_POOL_CONNECTIONS = 10
DEFAULT_POOL_MAXSIZE = 20
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_FACTOR = 0.3
DEFAULT_TIMEOUT = (10, 30)  # (connect, read)

# Phase 2: Memory management constants
DEFAULT_MAX_MEMORY_MB = 100
MEMORY_CHECK_INTERVAL = 100  # Check memory every N entries

# Phase 2: Adaptive polling constants
DEFAULT_MIN_POLL_SLEEP = 1.0
DEFAULT_MAX_POLL_SLEEP = 60.0
BACKOFF_MULTIPLIER = 1.5
SUCCESS_REDUCTION_FACTOR = 0.8

# Dynamic CT log discovery - fetched from Google's official list
CT_LOGS = {}

# Phase 3: Logging setup
logger = logging.getLogger('certpatrol')

def setup_logging(verbose: bool = False, quiet_warnings: bool = False) -> None:
    """
    Setup logging configuration based on verbosity settings.
    Maintains backward compatibility with print-based output.
    
    Args:
        verbose: Enable debug level logging
        quiet_warnings: Suppress warning level messages
    """
    # Remove existing handlers
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Create console handler
    console_handler = logging.StreamHandler()
    
    # Set logging level based on verbose and quiet settings
    if verbose:
        logger.setLevel(logging.DEBUG)
        console_handler.setLevel(logging.DEBUG)
    elif quiet_warnings:
        logger.setLevel(logging.ERROR)
        console_handler.setLevel(logging.ERROR)
    else:
        logger.setLevel(logging.INFO)
        console_handler.setLevel(logging.INFO)
    
    # Create formatter that mimics original print output
    formatter = logging.Formatter('%(message)s')
    console_handler.setFormatter(formatter)
    
    # Add handler to logger
    logger.addHandler(console_handler)
    logger.propagate = False

# Signal handling for graceful shutdown
class GracefulShutdownHandler:
    """
    Handles graceful shutdown on various signals (SIGTERM, SIGINT, etc.).
    
    This class manages the shutdown process by:
    - Catching termination signals
    - Saving current checkpoints
    - Cleaning up resources
    - Providing clean exit
    """
    
    def __init__(self):
        self.shutdown_requested = False
        self.checkpoints: Optional[Dict[str, int]] = None
        self.cleanup_functions: List[callable] = []
        
    def request_shutdown(self, signum: int, frame) -> None:
        """
        Signal handler that requests graceful shutdown.
        
        Args:
            signum: Signal number
            frame: Current stack frame
        """
        signal_names = {
            signal.SIGTERM: "SIGTERM",
            signal.SIGINT: "SIGINT",
            signal.SIGHUP: "SIGHUP",
        }
        signal_name = signal_names.get(signum, f"Signal {signum}")
        
        if not self.shutdown_requested:
            # Always show shutdown message regardless of quiet mode
            print(f"Received {signal_name}, initiating graceful shutdown...", flush=True)
            self.shutdown_requested = True
            
            # Save checkpoints if available
            if self.checkpoints is not None:
                try:
                    save_checkpoints(self.checkpoints)
                    print("Checkpoints saved successfully", flush=True)
                except CheckpointError as e:
                    print(f"Failed to save checkpoints during shutdown: {e}", flush=True)
            
            # Run cleanup functions
            for cleanup_func in self.cleanup_functions:
                try:
                    cleanup_func()
                except Exception as e:
                    print(f"Error during cleanup: {e}", flush=True)
        else:
            # Second signal, force exit
            print(f"Received second {signal_name}, forcing immediate exit", flush=True)
            sys.exit(1)
    
    def register_cleanup(self, cleanup_func: callable) -> None:
        """
        Register a cleanup function to be called during shutdown.
        
        Args:
            cleanup_func: Function to call during cleanup
        """
        self.cleanup_functions.append(cleanup_func)
    
    def set_checkpoints(self, checkpoints: Dict[str, int]) -> None:
        """
        Set the current checkpoints for potential saving during shutdown.
        
        Args:
            checkpoints: Current checkpoint data
        """
        self.checkpoints = checkpoints
    
    def should_shutdown(self) -> bool:
        """
        Check if shutdown has been requested.
        
        Returns:
            True if shutdown was requested, False otherwise
        """
        return self.shutdown_requested
    
    def setup_signal_handlers(self) -> None:
        """Setup signal handlers for graceful shutdown."""
        # Handle common termination signals
        signals_to_handle = [signal.SIGTERM, signal.SIGINT]
        
        # Add SIGHUP on Unix systems (not available on Windows)
        if hasattr(signal, 'SIGHUP'):
            signals_to_handle.append(signal.SIGHUP)
        
        for sig in signals_to_handle:
            signal.signal(sig, self.request_shutdown)

# Global shutdown handler instance
shutdown_handler = GracefulShutdownHandler()

# Phase 3: Configuration validation
def validate_config_args(args: argparse.Namespace) -> List[str]:
    """
    Validate command line arguments and configuration.
    
    This function performs comprehensive validation of all input parameters
    to catch configuration errors early and provide helpful error messages.
    
    Args:
        args: Parsed command line arguments
        
    Returns:
        List of validation error messages (empty if all valid)
    """
    errors = []
    
    # Validate pattern if provided (not required for cleanup operation)
    if hasattr(args, 'pattern') and args.pattern:
        try:
            re.compile(args.pattern, re.IGNORECASE)
        except re.error as e:
            errors.append(f"Invalid regex pattern: {e}")
    
    # Validate numeric parameters
    if hasattr(args, 'batch') and args.batch is not None:
        if args.batch <= 0:
            errors.append("Batch size must be positive")
        elif args.batch > 10000:
            errors.append("Batch size too large (max 10000)")
    
    if hasattr(args, 'poll_sleep') and args.poll_sleep is not None:
        if args.poll_sleep < 0:
            errors.append("Poll sleep cannot be negative")
        elif args.poll_sleep > 3600:
            errors.append("Poll sleep too large (max 3600 seconds)")
    
    if hasattr(args, 'max_memory_mb') and args.max_memory_mb is not None:
        if args.max_memory_mb <= 0:
            errors.append("Max memory must be positive")
        elif args.max_memory_mb < 10:
            errors.append("Max memory too small (min 10MB)")
        elif args.max_memory_mb > 10000:
            errors.append("Max memory too large (max 10GB)")
    
    if hasattr(args, 'min_poll_sleep') and args.min_poll_sleep is not None:
        if args.min_poll_sleep < 0:
            errors.append("Min poll sleep cannot be negative")
        elif args.min_poll_sleep > 300:
            errors.append("Min poll sleep too large (max 300 seconds)")
    
    if hasattr(args, 'max_poll_sleep') and args.max_poll_sleep is not None:
        if args.max_poll_sleep < 0:
            errors.append("Max poll sleep cannot be negative")
        elif args.max_poll_sleep > 3600:
            errors.append("Max poll sleep too large (max 3600 seconds)")
    
    # Cross-parameter validation
    if (hasattr(args, 'min_poll_sleep') and hasattr(args, 'max_poll_sleep') and 
        args.min_poll_sleep is not None and args.max_poll_sleep is not None):
        if args.max_poll_sleep < args.min_poll_sleep:
            errors.append("Max poll sleep must be >= min poll sleep")
    
    # Validate checkpoint prefix if provided
    if hasattr(args, 'checkpoint_prefix') and args.checkpoint_prefix:
        import string
        safe_chars = string.ascii_letters + string.digits + "_-"
        if not all(c in safe_chars for c in args.checkpoint_prefix):
            errors.append("Checkpoint prefix can only contain letters, digits, underscores, and hyphens")
        if len(args.checkpoint_prefix) > 50:
            errors.append("Checkpoint prefix too long (max 50 characters)")
    
    return errors

# Phase 1 Improvement: Custom exceptions for better error handling
class CertPatrolError(Exception):
    """
    Base exception for CertPatrol errors.
    
    All custom exceptions in CertPatrol inherit from this base class
    to allow for easy exception handling and categorization.
    """
    pass

class CheckpointError(CertPatrolError):
    """
    Raised when checkpoint operations fail.
    
    This includes scenarios such as:
    - Failed to create checkpoint directory
    - Corrupted checkpoint files
    - Invalid checkpoint data structure
    - Atomic write failures
    """
    pass

class CTLogError(CertPatrolError):
    """
    Raised when CT log operations fail.
    
    This includes scenarios such as:
    - Network errors when connecting to CT logs
    - Invalid responses from CT log endpoints
    - Malformed JSON data from CT logs
    - Authentication or rate limiting issues
    """
    pass

class MemoryError(CertPatrolError):
    """
    Raised when memory limits are exceeded.
    
    This custom memory error is separate from Python's built-in
    MemoryError to distinguish between system-level and
    application-level memory management issues.
    """
    pass

# Phase 2: HTTP Session Management with Connection Pooling
class HTTPSessionManager:
    """
    Manages HTTP sessions with connection pooling and retries.
    
    This class provides a centralized way to manage HTTP connections
    for CT log communication, implementing connection pooling for
    improved performance and retry strategies for better reliability.
    
    Attributes:
        timeout: Tuple of (connect_timeout, read_timeout) in seconds
        session: The underlying requests.Session object
    """
    
    def __init__(
        self, 
        pool_connections: int = DEFAULT_POOL_CONNECTIONS,
        pool_maxsize: int = DEFAULT_POOL_MAXSIZE,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_factor: float = DEFAULT_BACKOFF_FACTOR,
        timeout: Tuple[int, int] = DEFAULT_TIMEOUT
    ) -> None:
        """
        Initialize the HTTP session manager.
        
        Args:
            pool_connections: Number of connection pools to cache
            pool_maxsize: Maximum number of connections to save in the pool
            max_retries: Maximum number of retry attempts
            backoff_factor: Backoff factor for retry delays
            timeout: Tuple of (connect, read) timeout values in seconds
        """
        self.timeout = timeout
        self.session = self._create_session(pool_connections, pool_maxsize, max_retries, backoff_factor)
    
    def _create_session(
        self, 
        pool_connections: int, 
        pool_maxsize: int,
        max_retries: int, 
        backoff_factor: float
    ) -> requests.Session:
        """
        Create a requests session with connection pooling and retry strategy.
        
        Args:
            pool_connections: Number of connection pools to cache
            pool_maxsize: Maximum number of connections to save in the pool
            max_retries: Maximum number of retry attempts
            backoff_factor: Backoff factor for retry delays
            
        Returns:
            Configured requests.Session object
        """
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=max_retries,
            status_forcelist=[429, 500, 502, 503, 504],
            backoff_factor=backoff_factor,
            allowed_methods=["HEAD", "GET", "OPTIONS"]
        )
        
        # Configure HTTP adapter with connection pooling
        adapter = HTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=retry_strategy,
            pool_block=False
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({"User-Agent": USER_AGENT})
        
        return session
    
    def get(self, url: str, **kwargs) -> requests.Response:
        """
        Make a GET request using the managed session.
        
        Args:
            url: The URL to request
            **kwargs: Additional arguments passed to requests.get()
            
        Returns:
            Response object from the request
        """
        kwargs.setdefault('timeout', self.timeout)
        return self.session.get(url, **kwargs)
    
    def close(self) -> None:
        """Close the session and clean up connections."""
        if hasattr(self, 'session'):
            self.session.close()
    
    def __enter__(self) -> 'HTTPSessionManager':
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit with cleanup."""
        self.close()

# Phase 2: Adaptive Rate Limiting
class AdaptiveRateLimiter:
    """
    Manages adaptive polling intervals with exponential backoff on errors.
    
    This class implements an adaptive rate limiting strategy that:
    - Increases sleep intervals on consecutive errors (exponential backoff)
    - Decreases sleep intervals on consecutive successes
    - Maintains configurable minimum and maximum sleep bounds
    
    Attributes:
        current_sleep: Current sleep interval in seconds
        min_sleep: Minimum allowed sleep interval
        max_sleep: Maximum allowed sleep interval
        consecutive_errors: Count of consecutive error occurrences
        consecutive_successes: Count of consecutive successful operations
    """
    
    def __init__(
        self, 
        initial_sleep: float, 
        min_sleep: float = DEFAULT_MIN_POLL_SLEEP,
        max_sleep: float = DEFAULT_MAX_POLL_SLEEP
    ) -> None:
        """
        Initialize the adaptive rate limiter.
        
        Args:
            initial_sleep: Starting sleep interval in seconds
            min_sleep: Minimum allowed sleep interval in seconds
            max_sleep: Maximum allowed sleep interval in seconds
        """
        self.current_sleep = initial_sleep
        self.min_sleep = min_sleep
        self.max_sleep = max_sleep
        self.consecutive_errors = 0
        self.consecutive_successes = 0
    
    def on_success(self) -> None:
        """
        Called when an operation succeeds.
        
        Resets error counter and potentially reduces sleep interval
        after multiple consecutive successes.
        """
        self.consecutive_errors = 0
        self.consecutive_successes += 1
        
        # Gradually reduce sleep time on consecutive successes
        if self.consecutive_successes >= 3:
            self.current_sleep = max(
                self.min_sleep,
                self.current_sleep * SUCCESS_REDUCTION_FACTOR
            )
            self.consecutive_successes = 0
    
    def on_error(self) -> None:
        """
        Called when an operation fails.
        
        Resets success counter and increases sleep interval
        using exponential backoff strategy.
        """
        self.consecutive_successes = 0
        self.consecutive_errors += 1
        
        # Exponential backoff on consecutive errors
        self.current_sleep = min(
            self.max_sleep,
            self.current_sleep * (BACKOFF_MULTIPLIER ** self.consecutive_errors)
        )
    
    def sleep(self) -> None:
        """Sleep for the current adaptive interval."""
        time.sleep(self.current_sleep)
    
    def get_current_sleep(self) -> float:
        """
        Get the current sleep interval.
        
        Returns:
            Current sleep interval in seconds
        """
        return self.current_sleep

# Phase 2: Memory Monitor
class MemoryMonitor:
    """
    Monitors and manages memory usage during processing.
    
    This class provides memory monitoring capabilities to prevent
    excessive memory usage during certificate processing. It can
    trigger garbage collection and raise exceptions when limits
    are exceeded.
    
    Attributes:
        max_memory_bytes: Maximum allowed memory usage in bytes
        check_counter: Counter for periodic memory checks
    """
    
    def __init__(self, max_memory_mb: int = DEFAULT_MAX_MEMORY_MB) -> None:
        """
        Initialize the memory monitor.
        
        Args:
            max_memory_mb: Maximum allowed memory usage in megabytes
        """
        self.max_memory_bytes = max_memory_mb * 1024 * 1024
        self.check_counter = 0
    
    def check_memory(self) -> None:
        """
        Check current memory usage and trigger GC if needed.
        
        Raises:
            MemoryError: If memory usage exceeds the configured limit
                        even after garbage collection
        """
        self.check_counter += 1
        
        if self.check_counter % MEMORY_CHECK_INTERVAL == 0:
            try:
                import psutil  # type: ignore[import-untyped]
                process = psutil.Process()
                memory_info = process.memory_info()
                
                if memory_info.rss > self.max_memory_bytes:
                    # Force garbage collection
                    gc.collect()
                    
                    # Check again after GC
                    memory_info = process.memory_info()
                    if memory_info.rss > self.max_memory_bytes:
                        raise MemoryError(
                            f"Memory usage ({memory_info.rss / 1024 / 1024:.1f}MB) "
                            f"exceeds limit ({self.max_memory_bytes / 1024 / 1024:.1f}MB)"
                        )
            except ImportError:
                # psutil not available, use basic GC trigger
                if self.check_counter % (MEMORY_CHECK_INTERVAL * 10) == 0:
                    gc.collect()

# --- Phase 1: Certificate parsing with cryptography library ---

def _read_uint24(b: bytes, offset: int) -> Tuple[int, int]:
    """
    Read a 3-byte big-endian unsigned int, return (value, new_offset).
    
    Args:
        b: Byte array to read from
        offset: Starting position in the byte array
        
    Returns:
        Tuple of (parsed_value, new_offset)
        
    Raises:
        ValueError: If there are insufficient bytes remaining
    """
    if offset + 3 > len(b):
        raise ValueError("Truncated uint24")
    return (b[offset] << 16) | (b[offset+1] << 8) | b[offset+2], offset + 3

def parse_tls_cert_chain(extra_data_b64: str) -> List[bytes]:
    """
    Parse certificates from CT 'extra_data' (base64).
    CT logs concatenate DER certificates directly, not in TLS structure.
    Returns a list of DER cert bytes [leaf, intermediates...].
    
    Phase 1: Replaced manual ASN.1 parsing with cryptography library-based parsing
    Phase 2: Added memory efficiency improvements
    """
    import base64
    try:
        raw = base64.b64decode(extra_data_b64)
        if len(raw) < 10:  # Minimum reasonable certificate size
            return []
        
        certs = []
        pos = 0
        
        # Phase 2: Process certificates with memory awareness
        while pos < len(raw):
            try:
                # Look for ASN.1 SEQUENCE start (0x30) which indicates start of certificate
                if pos + 1 >= len(raw) or raw[pos] != 0x30:
                    pos += 1
                    continue
                
                # Use a more robust approach: try different certificate lengths
                min_cert_size = 100  # Very small certificates are unlikely
                max_cert_size = min(len(raw) - pos, 10 * 1024 * 1024)  # Max 10MB per cert
                
                cert_found = False
                
                # Try to find the correct certificate boundary by testing if we can parse it
                for try_end in range(pos + min_cert_size, min(pos + max_cert_size + 1, len(raw) + 1)):
                    try:
                        candidate_der = raw[pos:try_end]
                        
                        # Attempt to parse with cryptography library - this validates the DER structure
                        test_cert = x509.load_der_x509_certificate(candidate_der)
                        
                        # If we got here, the certificate parsed successfully
                        certs.append(candidate_der)
                        pos = try_end
                        cert_found = True
                        break
                        
                    except (ValueError, TypeError, x509.ExtensionNotFound, x509.InvalidVersion) as e:
                        # These are expected for partial certificates or invalid DER
                        continue
                    except Exception:
                        # Unexpected error, skip this attempt
                        continue
                
                if not cert_found:
                    # No valid certificate found starting at this position, advance by 1
                    pos += 1
                    
            except Exception:
                # If anything goes wrong, advance position and continue
                pos += 1
                continue
        
        return certs
        
    except Exception:
        # Fallback: if base64 decode fails or other fundamental error
        return []

def extract_domains_from_der(der_bytes: bytes) -> List[str]:
    """
    Extract DNS names from SAN; if absent, fallback to CN when it looks like a DNS name.
    Returns lowercased, Unicode (IDNA-decoded) domains.
    """
    domains = []
    
    # Suppress warnings for certificates with non-compliant serial numbers
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        warnings.filterwarnings("ignore", message=".*serial number.*")
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

# --- Phase 2: Enhanced Dynamic CT log discovery with connection pooling ---

def fetch_usable_ct_logs(verbose: bool = False, session_manager: HTTPSessionManager = None) -> Dict[str, str]:
    """
    Fetch the current list of usable CT logs from Google's official list.
    Returns a dict mapping log names to base URLs.
    
    Phase 2: Uses HTTP session manager for connection pooling.
    """
    close_session = False
    if session_manager is None:
        session_manager = HTTPSessionManager()
        close_session = True
    
    try:
        if verbose:
            logger.info("Fetching current CT log list from Google...")
        
        resp = session_manager.get(LOG_LIST_URL)
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
                        logger.info(f"Found usable log: {name} -> {url}")
        
        if verbose:
            logger.info(f"Found {len(usable_logs)} usable CT logs")
        
        return usable_logs
        
    except requests.RequestException as e:
        if verbose:
            logger.warning(f"Network error fetching CT log list: {e}")
        # Fallback to a known working log
        return {"xenon2023": "https://ct.googleapis.com/logs/xenon2023"}
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        if verbose:
            logger.warning(f"Failed to parse CT log list: {e}")
        # Fallback to a known working log
        return {"xenon2023": "https://ct.googleapis.com/logs/xenon2023"}
    except Exception as e:
        if verbose:
            logger.warning(f"Unexpected error fetching CT log list: {e}")
        # Fallback to a known working log
        return {"xenon2023": "https://ct.googleapis.com/logs/xenon2023"}
    finally:
        if close_session:
            session_manager.close()

def save_debug_response(name: str, entry: dict, absolute_idx: int) -> None:
    """
    Save a CT log entry to a debug file for analysis.
    
    Args:
        name: Name of the CT log
        entry: The CT log entry data to save
        absolute_idx: Absolute index of the entry in the log
    """
    debug_dir = "debug_responses"
    try:
        if not os.path.exists(debug_dir):
            os.makedirs(debug_dir)
        
        filename = f"{debug_dir}/{name}_{absolute_idx}.json"
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(entry, f, indent=2, default=str)
        logger.debug(f"Saved response to {filename}")
    except (OSError, IOError, TypeError, ValueError) as e:
        logger.debug(f"Failed to save response: {e}")

# --- Phase 2: Enhanced CT polling with connection pooling ---

def get_sth(base_url: str, session_manager: HTTPSessionManager) -> int:
    """
    Return current tree_size of the CT log.
    Phase 2: Uses HTTP session manager for connection pooling.
    """
    try:
        r = session_manager.get(f"{base_url}/ct/v1/get-sth")
        r.raise_for_status()
        data = r.json()
        return int(data["tree_size"])
    except requests.RequestException as e:
        raise CTLogError(f"Network error getting STH from {base_url}: {e}")
    except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
        raise CTLogError(f"Invalid STH response from {base_url}: {e}")

def get_entries(base_url: str, start: int, end: int, session_manager: HTTPSessionManager) -> List[dict]:
    """
    Fetch entries [start..end] inclusive (may return fewer).
    Phase 2: Uses HTTP session manager for connection pooling.
    """
    try:
        r = session_manager.get(
            f"{base_url}/ct/v1/get-entries",
            params={"start": start, "end": end}
        )
        r.raise_for_status()
        data = r.json()
        return data.get("entries", [])
    except requests.RequestException as e:
        raise CTLogError(f"Network error getting entries from {base_url}: {e}")
    except (json.JSONDecodeError, KeyError, TypeError) as e:
        raise CTLogError(f"Invalid entries response from {base_url}: {e}")

# --- Phase 1: Enhanced Checkpoint Management ---

def ensure_checkpoint_dir():
    """Ensure the checkpoints directory exists."""
    try:
        if not os.path.exists(CHECKPOINT_DIR):
            os.makedirs(CHECKPOINT_DIR)
    except OSError as e:
        raise CheckpointError(f"Failed to create checkpoint directory: {e}")

def validate_checkpoint_data(data: Any) -> Dict[str, int]:
    """
    Validate checkpoint data structure and content.
    Returns validated data or raises CheckpointError.
    """
    if not isinstance(data, dict):
        raise CheckpointError("Checkpoint data must be a dictionary")
    
    validated = {}
    for key, value in data.items():
        if not isinstance(key, str):
            raise CheckpointError(f"Checkpoint key must be string, got {type(key)}")
        if not isinstance(value, (int, float)):
            raise CheckpointError(f"Checkpoint value must be numeric, got {type(value)}")
        
        # Convert to int and validate range
        try:
            int_value = int(value)
            if int_value < 0:
                raise CheckpointError(f"Checkpoint value must be non-negative, got {int_value}")
            validated[key] = int_value
        except (ValueError, OverflowError) as e:
            raise CheckpointError(f"Invalid checkpoint value for {key}: {e}")
    
    return validated

def load_checkpoints() -> Dict[str, int]:
    """
    Enhanced checkpoint loading with validation.
    
    Returns:
        Dictionary mapping log names to checkpoint positions
    """
    ensure_checkpoint_dir()
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, "r", encoding="utf-8") as fh:
                raw_data = json.load(fh)
            return validate_checkpoint_data(raw_data)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning(f"Corrupted checkpoint file, starting fresh: {e}")
            return {}
        except CheckpointError as e:
            logger.warning(f"Invalid checkpoint data, starting fresh: {e}")
            return {}
    return {}

def save_checkpoints(cp: Dict[str, int]) -> None:
    """
    Enhanced atomic write with validation and integrity checks.
    
    Args:
        cp: Dictionary mapping log names to checkpoint positions
        
    Raises:
        CheckpointError: If checkpoint data is invalid or save operation fails
    """
    ensure_checkpoint_dir()
    
    # Validate checkpoint data before saving
    try:
        validated_cp = validate_checkpoint_data(cp)
    except CheckpointError as e:
        raise CheckpointError(f"Cannot save invalid checkpoint data: {e}")
    
    tmp = CHECKPOINT_FILE + ".tmp"
    max_retries = 3
    retry_delay = 0.1
    
    for attempt in range(max_retries):
        try:
            # Write to temporary file
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(validated_cp, fh, indent=2)
            
            # Verify the file was written correctly by reading it back
            try:
                with open(tmp, "r", encoding="utf-8") as fh:
                    verify_data = json.load(fh)
                validate_checkpoint_data(verify_data)
            except Exception as e:
                raise CheckpointError(f"Checkpoint verification failed: {e}")
            
            # Atomically replace the original file
            os.replace(tmp, CHECKPOINT_FILE)
            return
            
        except (OSError, IOError, CheckpointError) as e:
            if attempt < max_retries - 1:
                time.sleep(retry_delay)
                retry_delay *= 2  # Exponential backoff
                continue
            else:
                # Clean up temp file on final failure
                try:
                    if os.path.exists(tmp):
                        os.unlink(tmp)
                except OSError:
                    pass
                raise CheckpointError(f"Failed to save checkpoints after {max_retries} attempts: {e}")

def cleanup_checkpoint_file() -> None:
    """
    Clean up checkpoint file when process exits.
    
    This function is typically called during program shutdown
    to remove process-specific checkpoint files.
    """
    try:
        if os.path.exists(CHECKPOINT_FILE):
            os.unlink(CHECKPOINT_FILE)
    except OSError as e:
        logger.warning(f"Failed to cleanup checkpoint file: {e}")

def cleanup_orphaned_checkpoints() -> None:
    """
    Clean up checkpoint files from processes that are no longer running.
    
    This function scans for checkpoint files and removes those belonging
    to processes that are no longer active.
    """
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
                    logger.info(f"Removed orphaned checkpoint: {filename}")
        except Exception as e:
            logger.warning(f"Failed to process checkpoint file {checkpoint_file}: {e}")
    
    if cleaned > 0:
        logger.info(f"Cleaned up {cleaned} orphaned checkpoint files")
    else:
        logger.info("No orphaned checkpoint files found")

# --- Phase 2: Enhanced streaming entry processor ---

def process_entries_streaming(
    entries: List[dict],
    pattern: re.Pattern,
    match_scope: str,
    verbose: bool,
    debug_all: bool,
    quiet_parse_errors: bool,
    quiet_warnings: bool,
    log_name: str,
    start_idx: int,
    memory_monitor: MemoryMonitor
) -> Iterator[str]:
    """
    Process CT log entries in streaming fashion to optimize memory usage.
    Phase 2: Added memory monitoring and streaming processing.
    
    Note: When match_scope == "etld1", the pattern is matched against the registrable
    base domain (eTLD+1), not the full domain. For example:
    - Full domain: "tom-tochito.workers.dev" 
    - Registrable domain: "workers.dev"
    - Pattern should match "workers.dev", not ".*\\.workers\\.dev$"
    """
    for i, entry in enumerate(entries):
        absolute_idx = start_idx + i
        
        # Phase 2: Check memory usage periodically
        memory_monitor.check_memory()
        
        try:
            chain = parse_tls_cert_chain(entry["extra_data"])
            if not chain:
                if verbose:
                    logger.debug(f"{log_name}@{absolute_idx}: no valid chain parsed")
                    # Save first few failed responses for debugging
                    if absolute_idx % 100 == 0:  # Save every 100th failed entry
                        save_debug_response(log_name, entry, absolute_idx)
                continue
                
            leaf_der = chain[0]  # end-entity first
            domains = extract_domains_from_der(leaf_der)
            
            if verbose and debug_all and domains:
                logger.debug(f"{log_name}@{absolute_idx}: found domains: {domains}")
                
            # Process matches immediately to reduce memory footprint
            for d in domains:
                target = registrable_domain(d) if match_scope == "etld1" else d
                if pattern.search(target):
                    yield d
                    # If verbose, also yield metadata
                    if verbose:
                        ts = entry.get("sct", {}).get("timestamp")
                        yield f"# matched {d} | log={log_name} idx={absolute_idx} ts={ts}"
            
            # Phase 2: Clear references to help with memory management
            del entry
            if i % 50 == 0:  # Force GC every 50 entries
                gc.collect()
                
        except Exception as e:
            if verbose and not quiet_warnings and not quiet_parse_errors:
                logger.warning(f"{log_name}@{absolute_idx}: parse failed: {e}")
                # Save first few failed responses for debugging
                if absolute_idx % 100 == 0:
                    save_debug_response(log_name, entry, absolute_idx)
            continue

# --- Phase 2: Main log tailing function with performance improvements ---

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
    max_memory_mb: int = DEFAULT_MAX_MEMORY_MB,
    min_poll_sleep: float = DEFAULT_MIN_POLL_SLEEP,
    max_poll_sleep: float = DEFAULT_MAX_POLL_SLEEP,
):
    """
    Main log tailing function.
    Phase 2: Added HTTP connection pooling, adaptive rate limiting, and memory management.
    """
    if ct_logs is None:
        ct_logs = CT_LOGS

    # Phase 2: Initialize performance components
    session_manager = HTTPSessionManager()
    rate_limiter = AdaptiveRateLimiter(poll_sleep, min_poll_sleep, max_poll_sleep)
    memory_monitor = MemoryMonitor(max_memory_mb)
    
    # Register session cleanup with shutdown handler
    shutdown_handler.register_cleanup(session_manager.close)
    
    try:
        checkpoints = load_checkpoints()
    except CheckpointError as e:
        logger.error(f"Failed to load checkpoints: {e}")
        return
    finally:
        # Ensure session cleanup on any exit
        import atexit
        atexit.register(session_manager.close)

    # Initialize checkpoints at current tree_size (tail-from-now semantics)
    for name in logs:
        # Check for shutdown during initialization
        if shutdown_handler.should_shutdown():
            print("Shutdown requested during initialization", flush=True)
            return
            
        if name not in ct_logs:
            if verbose:
                logger.warning(f"Unknown log: {name}")
            continue
        base = ct_logs[name]
        if name not in checkpoints:
            try:
                tree_size = get_sth(base, session_manager)
                checkpoints[name] = tree_size  # next index to fetch
                if verbose:
                    logger.info(f"{name}: starting at index {tree_size}")
                rate_limiter.on_success()  # STH fetch succeeded
            except CTLogError as e:
                logger.warning(f"{name}: failed to init STH: {e}")
                checkpoints[name] = 0
                rate_limiter.on_error()  # STH fetch failed

    try:
        save_checkpoints(checkpoints)
    except CheckpointError as e:
        logger.error(f"Failed to save initial checkpoints: {e}")
        return

    # Set up checkpoints for graceful shutdown
    shutdown_handler.set_checkpoints(checkpoints)

    if verbose:
        logger.info(f"Using adaptive polling: {min_poll_sleep}s - {max_poll_sleep}s")
        logger.info(f"Memory limit: {max_memory_mb}MB")

    while True:
        # Check for graceful shutdown request
        if shutdown_handler.should_shutdown():
            print("Graceful shutdown requested, exiting main loop", flush=True)
            break
        any_progress = False
        loop_start_time = time.time()
        
        for name in logs:
            if name not in ct_logs:
                continue
            base = ct_logs[name]
            
            # Phase 2: Check memory before processing each log
            try:
                memory_monitor.check_memory()
            except MemoryError as e:
                logger.error(str(e))
                # Force a more aggressive GC and continue
                gc.collect()
                continue
            
            # Determine target size
            try:
                tree_size = get_sth(base, session_manager)
                rate_limiter.on_success()  # STH fetch succeeded
            except CTLogError as e:
                if verbose:
                    logger.warning(f"{name}: get-sth failed: {e}")
                rate_limiter.on_error()  # STH fetch failed
                continue

            next_idx = checkpoints.get(name, 0)
            if next_idx >= tree_size:
                # nothing new
                continue

            any_progress = True
            # Fetch in batches up to current tree_size-1
            end_idx = min(next_idx + batch - 1, tree_size - 1)

            try:
                entries = get_entries(base, next_idx, end_idx, session_manager)
                rate_limiter.on_success()  # Entries fetch succeeded
            except CTLogError as e:
                if verbose:
                    logger.warning(f"{name}: get-entries {next_idx}-{end_idx} failed: {e}")
                rate_limiter.on_error()  # Entries fetch failed
                continue

            # Process entries with streaming
            if verbose and debug_all and entries:
                logger.debug(f"{name}: processing {len(entries)} entries from {next_idx} to {end_idx}")
            
            # Phase 2: Use streaming processor for better memory efficiency
            try:
                for result in process_entries_streaming(
                    entries, pattern, match_scope, verbose, debug_all,
                    quiet_parse_errors, quiet_warnings, name, next_idx, memory_monitor
                ):
                    print(result, flush=True)
            except MemoryError as e:
                logger.error(f"Memory limit exceeded processing {name}: {e}")
                # Skip this batch and continue
                continue

            try:
                checkpoints[name] = end_idx + 1
                save_checkpoints(checkpoints)
                # Update shutdown handler with latest checkpoints
                shutdown_handler.set_checkpoints(checkpoints)
            except CheckpointError as e:
                logger.error(f"Failed to save checkpoints for {name}: {e}")
                # Continue processing other logs even if checkpoint save fails

        # Phase 2: Adaptive sleep based on progress and errors
        if not any_progress:
            if verbose:
                current_sleep = rate_limiter.get_current_sleep()
                logger.debug(f"No progress, sleeping for {current_sleep:.1f}s")
            
            # Sleep in smaller chunks to allow for responsive shutdown
            sleep_time = rate_limiter.get_current_sleep()
            sleep_chunk = 0.5  # Check for shutdown every 0.5 seconds
            while sleep_time > 0 and not shutdown_handler.should_shutdown():
                chunk = min(sleep_chunk, sleep_time)
                time.sleep(chunk)
                sleep_time -= chunk
        else:
            # Had progress, reduce sleep time
            rate_limiter.on_success()
            
        # Phase 2: Show performance stats periodically
        if verbose and any_progress:
            loop_time = time.time() - loop_start_time
            logger.debug(f"Loop completed in {loop_time:.2f}s, current poll interval: {rate_limiter.get_current_sleep():.1f}s")

def main() -> int:
    """
    Main entry point for CertPatrol.
    
    Returns:
        Exit code (0 for success, non-zero for errors)
    """
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
        help="Initial seconds to sleep between polls (default: 3.0, adaptive)"
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
        help="Match against registrable base domain instead of full domain (e.g., 'workers.dev' not 'example.workers.dev')"
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
    # Phase 2: New performance and memory options
    parser.add_argument(
        "--max-memory-mb", "-m",
        type=int,
        default=DEFAULT_MAX_MEMORY_MB,
        help=f"Maximum memory usage in MB for batch processing (default: {DEFAULT_MAX_MEMORY_MB})"
    )
    parser.add_argument(
        "--min-poll-sleep", "-mn",
        type=float,
        default=DEFAULT_MIN_POLL_SLEEP,
        help=f"Minimum poll sleep time for adaptive polling (default: {DEFAULT_MIN_POLL_SLEEP})"
    )
    parser.add_argument(
        "--max-poll-sleep", "-mx",
        type=float,
        default=DEFAULT_MAX_POLL_SLEEP,
        help=f"Maximum poll sleep time for adaptive polling (default: {DEFAULT_MAX_POLL_SLEEP})"
    )
    parser.add_argument(
        "--help", "-h",
        action="store_true",
        help="Show this help message and exit"
    )

    args = parser.parse_args()
    
    # Phase 3: Setup logging early (before any output)
    setup_logging(verbose=getattr(args, 'verbose', False), 
                  quiet_warnings=getattr(args, 'quiet_warnings', False))
    
    # Setup signal handlers for graceful shutdown
    shutdown_handler.setup_signal_handlers()
    
    # Handle help command
    if args.help:
        print(__doc__)
        return 0
    
    # Handle cleanup command
    if args.cleanup_checkpoints:
        try:
            cleanup_orphaned_checkpoints()
            return 0
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            return 1
    
    # Validate that pattern is provided for normal operation
    if not args.pattern:
        logger.error("--pattern/-p is required (unless using --cleanup-checkpoints)")
        return 1
    
    # Phase 3: Use comprehensive validation function
    validation_errors = validate_config_args(args)
    if validation_errors:
        for error in validation_errors:
            logger.error(f"Configuration error: {error}")
        return 1
        
    # Adjust poll sleep if outside adaptive range (with warning)
    if args.poll_sleep < args.min_poll_sleep or args.poll_sleep > args.max_poll_sleep:
        logger.warning(f"Poll sleep ({args.poll_sleep}) outside adaptive range [{args.min_poll_sleep}, {args.max_poll_sleep}], adjusting")
        args.poll_sleep = max(args.min_poll_sleep, min(args.max_poll_sleep, args.poll_sleep))
    
    # Set checkpoint file with custom prefix if provided
    global CHECKPOINT_FILE
    if args.checkpoint_prefix:
        CHECKPOINT_FILE = os.path.join(CHECKPOINT_DIR, f"certpatrol_checkpoints_{args.checkpoint_prefix}_{os.getpid()}.json")
    
    # Register cleanup function to remove checkpoint file on exit
    import atexit
    atexit.register(cleanup_checkpoint_file)
    
    # Compile regex pattern (already validated by validate_config_args)
    try:
        pattern = re.compile(args.pattern, re.IGNORECASE)
    except re.error as e:
        logger.error(f"Invalid regex pattern: {e}")
        return 1

    # Phase 2: Fetch current usable CT logs with session management
    try:
        with HTTPSessionManager() as session_manager:
            ct_logs = fetch_usable_ct_logs(verbose=args.verbose, session_manager=session_manager)
        if not ct_logs:
            logger.error("No usable CT logs found")
            return 1
    except Exception as e:
        logger.error(f"Failed to fetch CT logs: {e}")
        return 1

    # Use specified logs or default to all usable logs
    if args.logs is None:
        logs_to_use = list(ct_logs.keys())
    else:
        logs_to_use = args.logs
        # Validate log names
        invalid_logs = [name for name in logs_to_use if name not in ct_logs]
        if invalid_logs:
            logger.error(f"Unknown log(s): {', '.join(invalid_logs)}")
            logger.info(f"Available logs: {', '.join(sorted(ct_logs.keys()))}")
            return 1

    if args.verbose:
        logger.info(f"Tailing logs: {', '.join(logs_to_use)}")
        logger.info(f"Pattern: {args.pattern}")
        logger.info(f"Batch size: {args.batch}")
        logger.info(f"Initial poll sleep: {args.poll_sleep}s")
        logger.info(f"Adaptive polling range: {args.min_poll_sleep}s - {args.max_poll_sleep}s")
        logger.info(f"Memory limit: {args.max_memory_mb}MB")
        if args.checkpoint_prefix:
            logger.info(f"Checkpoint prefix: {args.checkpoint_prefix}")

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
            quiet_parse_errors=args.quiet_parse_errors,
            max_memory_mb=args.max_memory_mb,
            min_poll_sleep=args.min_poll_sleep,
            max_poll_sleep=args.max_poll_sleep,
        )
        
        # If we exit the tail_logs normally, it was due to graceful shutdown
        if shutdown_handler.should_shutdown():
            print("Graceful shutdown completed successfully", flush=True)
            return 0
    except KeyboardInterrupt:
        # This should rarely happen now due to signal handling, but handle it gracefully
        logger.info("Interrupted by user (KeyboardInterrupt)")
        # Make sure checkpoints are saved
        if hasattr(shutdown_handler, 'checkpoints') and shutdown_handler.checkpoints:
            try:
                save_checkpoints(shutdown_handler.checkpoints)
                logger.info("Final checkpoints saved")
            except CheckpointError as e:
                logger.error(f"Failed to save final checkpoints: {e}")
        return 0
    except CheckpointError as e:
        logger.error(f"Checkpoint error: {e}")
        return 1
    except CTLogError as e:
        logger.error(f"CT log error: {e}")
        return 1
    except MemoryError as e:
        logger.error(f"Memory error: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1

if __name__ == "__main__":
    exit(main())