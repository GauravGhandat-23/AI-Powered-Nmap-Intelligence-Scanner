"""
scanner.py — Secure Nmap execution engine for NmapAI Intelligence Scanner
"""

import subprocess
import shutil
import shlex
import platform
import time
from typing import Optional, List
from config import DEFAULT_TIMEOUT, SCAN_TYPES
from utils import setup_logger, validate_target, validate_port_range

logger = setup_logger("scanner")


class NmapNotFoundError(RuntimeError):
    """Raised when Nmap binary is not available on the system."""


class ScanTimeoutError(RuntimeError):
    """Raised when an Nmap scan exceeds its timeout."""


class InvalidTargetError(ValueError):
    """Raised when target validation fails."""


# ─── Nmap Availability ────────────────────────────────────────────────────────
def is_nmap_installed() -> bool:
    """Return True if nmap binary is available in PATH."""
    return shutil.which("nmap") is not None


def get_nmap_version() -> str:
    """Return the installed Nmap version string."""
    try:
        result = subprocess.run(
            ["nmap", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        first_line = result.stdout.splitlines()[0] if result.stdout else "Unknown"
        return first_line
    except Exception as exc:
        logger.warning("Could not determine Nmap version: %s", exc)
        return "Unknown"


# ─── Argument Builder ─────────────────────────────────────────────────────────
def build_nmap_command(
    target: str,
    scan_type: str,
    port_range: str,
    custom_args: str = "",
    extra_flags: Optional[List[str]] = None,
) -> List[str]:
    """
    Construct the Nmap command as a list of tokens (safe for subprocess).

    Args:
        target:      Validated IP / hostname / CIDR.
        scan_type:   Key from SCAN_TYPES config dict.
        port_range:  Port range string, e.g. '1-1024'.
        custom_args: Raw flag string for 'Custom Arguments' mode.
        extra_flags: Additional switches to append (e.g. ['-oX', '-']).

    Returns:
        List[str] suitable for subprocess.run().
    """
    cmd = ["nmap"]

    if scan_type == "Custom Arguments":
        if not custom_args.strip():
            raise ValueError("Custom Arguments mode requires non-empty arguments.")
        # Split safely, no shell expansion
        cmd += shlex.split(custom_args)
    else:
        template = SCAN_TYPES[scan_type]["args"]
        args_str = template.replace("{ports}", port_range)
        cmd += shlex.split(args_str)
        # Append port range only if not already embedded in the template
        if "{ports}" not in template and "-p" not in args_str and port_range:
            cmd += ["-p", port_range]

    # Always output XML to stdout for reliable parsing
    cmd += ["-oX", "-"]

    if extra_flags:
        cmd += extra_flags

    cmd.append(target)

    logger.debug("Built command: %s", " ".join(cmd))
    return cmd


# ─── Core Scanner ─────────────────────────────────────────────────────────────
class NmapScanner:
    """
    Encapsulates a single Nmap scan lifecycle:
    validate → build command → execute → return raw XML + metadata.
    """

    def __init__(
        self,
        target: str,
        scan_type: str,
        port_range: str = "1-1024",
        custom_args: str = "",
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.target = target.strip()
        self.scan_type = scan_type
        self.port_range = port_range.strip()
        self.custom_args = custom_args.strip()
        self.timeout = timeout
        self._xml_output: str = ""
        self._stderr_output: str = ""
        self._duration: float = 0.0
        self._returncode: int = -1

    # ── validation ─────────────────────────────────────────────────────────────
    def _validate(self) -> None:
        ok, err = validate_target(self.target)
        if not ok:
            raise InvalidTargetError(err)

        if self.scan_type != "Custom Arguments":
            ok2, err2 = validate_port_range(self.port_range)
            if not ok2:
                raise InvalidTargetError(f"Port range error: {err2}")

        if not is_nmap_installed():
            raise NmapNotFoundError(
                "Nmap is not installed or not in PATH. "
                "Install it from https://nmap.org/download.html"
            )

    # ── execution ──────────────────────────────────────────────────────────────
    def run(self) -> dict:
        """
        Run the Nmap scan.

        Returns a result dict with keys:
            success, xml_output, stderr, duration_seconds, command, returncode,
            target, scan_type, port_range, timestamp
        """
        self._validate()

        cmd = build_nmap_command(
            target=self.target,
            scan_type=self.scan_type,
            port_range=self.port_range,
            custom_args=self.custom_args,
        )

        logger.info(
            "Starting %s on target '%s' with port range '%s'",
            self.scan_type, self.target, self.port_range,
        )

        start = time.monotonic()

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            logger.error("Scan timed out after %d seconds.", self.timeout)
            raise ScanTimeoutError(
                f"Scan exceeded the {self.timeout}s timeout. "
                "Try a smaller port range or a quicker scan type."
            )
        except PermissionError:
            logger.error("Permission denied. OS detection / raw sockets require root.")
            raise PermissionError(
                "This scan type requires elevated privileges (sudo/root).\n"
                "On Linux/macOS run: sudo streamlit run app.py\n"
                "On Windows: run the terminal as Administrator."
            )
        except FileNotFoundError:
            raise NmapNotFoundError("Nmap binary not found. Install Nmap and retry.")
        except Exception as exc:
            logger.exception("Unexpected error during scan: %s", exc)
            raise

        self._duration = time.monotonic() - start
        self._xml_output = proc.stdout
        self._stderr_output = proc.stderr
        self._returncode = proc.returncode

        if proc.returncode not in (0, 1):
            # returncode 1 is used by Nmap for some legitimate warnings
            stderr_snippet = (proc.stderr or "")[:400]
            logger.warning("Nmap exited with code %d: %s", proc.returncode, stderr_snippet)
            if not proc.stdout.strip():
                raise RuntimeError(
                    f"Nmap returned exit code {proc.returncode}.\n"
                    f"Stderr: {stderr_snippet}"
                )

        logger.info(
            "Scan completed in %.1f seconds (returncode=%d)",
            self._duration, self._returncode,
        )

        return self._build_result(cmd)

    # ── result packaging ────────────────────────────────────────────────────────
    def _build_result(self, cmd: List[str]) -> dict:
        from utils import now_str
        return {
            "success": True,
            "xml_output": self._xml_output,
            "stderr": self._stderr_output,
            "duration_seconds": round(self._duration, 2),
            "command": " ".join(cmd),
            "returncode": self._returncode,
            "target": self.target,
            "scan_type": self.scan_type,
            "port_range": self.port_range,
            "timestamp": now_str(),
            "platform": platform.system(),
            "nmap_version": get_nmap_version(),
        }