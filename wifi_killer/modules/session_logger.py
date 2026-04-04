"""
modules/session_logger.py -- Session logging for Wifi-Killer.

Records timestamped actions (scans, attacks, configuration changes, etc.)
into per-session JSONL files for auditing and post-analysis.

**This tool is intended for educational and authorized security-testing
purposes only.**  Always obtain explicit written permission before
analysing or interacting with networks you do not own.

Usage
-----
    from wifi_killer.modules.session_logger import get_session_logger

    logger = get_session_logger()
    logger.log("scan_start", {"interface": "wlan0", "mode": "fast"})
    logger.log("scan_complete", {"hosts_found": 12})

    entries = logger.get_entries()
    logger.export("/tmp/session_export.json", fmt="json")
    logger.close()
"""

from __future__ import annotations

import json
import os
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


_DEFAULT_SESSION_DIR = os.path.join(
    os.path.expanduser("~"), ".wifi_killer", "sessions"
)


class SessionLogger:
    """Thread-safe JSONL session logger.

    Each instance manages a single session file.  Every call to
    :meth:`log` appends one JSON line to the file.  The file is created
    lazily on the first write so that instantiation alone never raises.

    Parameters
    ----------
    session_dir :
        Directory in which session files are stored.  Defaults to
        ``~/.wifi_killer/sessions/``.  Created automatically when it does
        not exist.
    """

    def __init__(self, session_dir: Optional[str] = None) -> None:
        self._session_dir: str = session_dir or _DEFAULT_SESSION_DIR
        self._lock: threading.Lock = threading.Lock()

        # Build a unique file name based on the current timestamp.
        timestamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
        self._session_file: str = os.path.join(
            self._session_dir, f"session_{timestamp}.jsonl"
        )

        # Eagerly create the directory so that permission errors surface
        # early, but never crash -- just warn.
        self._ensure_directory()

        # Record the session-start event.
        self.log("session_start")

    # ------------------------------------------------------------------ #
    # Internal helpers                                                      #
    # ------------------------------------------------------------------ #

    def _ensure_directory(self) -> None:
        """Create the session directory if it does not already exist."""
        try:
            os.makedirs(self._session_dir, exist_ok=True)
        except OSError as exc:
            print(
                f"[session_logger] WARNING: cannot create session directory "
                f"'{self._session_dir}': {exc}",
                file=sys.stderr,
            )

    def _write_line(self, line: str) -> None:
        """Append a single line to the session file.

        Errors are caught and reported to *stderr* so that a logging
        failure never interrupts the main application.
        """
        try:
            with open(self._session_file, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError as exc:
            print(
                f"[session_logger] WARNING: cannot write to "
                f"'{self._session_file}': {exc}",
                file=sys.stderr,
            )

    # ------------------------------------------------------------------ #
    # Public API                                                            #
    # ------------------------------------------------------------------ #

    @property
    def session_path(self) -> str:
        """Return the absolute path to the current session file."""
        return self._session_file

    def log(self, action: str, details: Optional[dict] = None) -> None:
        """Append a timestamped entry to the session log.

        Parameters
        ----------
        action :
            Short identifier for the event, e.g. ``"scan_start"``,
            ``"attack_stop"``, ``"config_change"``.
        details :
            Optional dictionary of additional context to attach to the
            entry.
        """
        entry: dict = {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "action": action,
        }
        if details is not None:
            entry["details"] = details

        with self._lock:
            self._write_line(json.dumps(entry, default=str))

    def get_entries(self) -> list[dict]:
        """Read and return every entry from the current session file.

        Returns an empty list when the file does not exist or cannot be
        read.
        """
        entries: list[dict] = []
        try:
            with open(self._session_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            # Skip malformed lines silently.
                            continue
        except OSError as exc:
            print(
                f"[session_logger] WARNING: cannot read "
                f"'{self._session_file}': {exc}",
                file=sys.stderr,
            )
        return entries

    def export(self, path: str, fmt: str = "json") -> None:
        """Export the session log to *path* in the requested format.

        Parameters
        ----------
        path :
            Destination file path.  Parent directories are created
            automatically.
        fmt :
            ``"json"`` (default) writes a pretty-printed JSON array.
            ``"text"`` writes a human-readable plain-text listing.

        Raises
        ------
        ValueError
            If *fmt* is not one of the supported values.
        """
        fmt = fmt.lower().strip()
        if fmt not in ("json", "text", "txt"):
            raise ValueError(
                f"Unknown export format '{fmt}'. Choose: json, text"
            )

        entries = self.get_entries()

        if fmt == "json":
            content = json.dumps(entries, indent=2, default=str)
        else:
            lines: list[str] = []
            sep = "-" * 60
            lines.append(f"Session: {self._session_file}")
            lines.append(f"Entries: {len(entries)}")
            lines.append(sep)
            for entry in entries:
                ts = entry.get("timestamp", "?")
                action = entry.get("action", "?")
                details = entry.get("details")
                detail_str = f"  {json.dumps(details, default=str)}" if details else ""
                lines.append(f"[{ts}] {action}{detail_str}")
            lines.append(sep)
            content = "\n".join(lines) + "\n"

        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)

        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(content)
        except OSError as exc:
            print(
                f"[session_logger] WARNING: cannot export to '{path}': {exc}",
                file=sys.stderr,
            )

    def close(self) -> None:
        """Log a ``session_end`` event, marking the session as finished."""
        self.log("session_end")


# ------------------------------------------------------------------ #
# Module-level singleton                                                #
# ------------------------------------------------------------------ #

session_logger: Optional[SessionLogger] = None


def get_session_logger(session_dir: Optional[str] = None) -> SessionLogger:
    """Return the module-level :class:`SessionLogger` singleton.

    The logger is created lazily on the first call.  Subsequent calls
    return the same instance (the *session_dir* argument is only used
    during initial creation).
    """
    global session_logger
    if session_logger is None:
        session_logger = SessionLogger(session_dir=session_dir)
    return session_logger
