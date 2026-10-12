import os
import sys
import csv
import uuid
import time
import hashlib
import getpass
import platform
import socket
import difflib
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
from datetime import datetime, timezone

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────
APP_NAME    = "FileGuard"
APP_VERSION = "1.0.0"

BASE_DIR  = Path(__file__).parent
DOCS_DIR  = BASE_DIR / "docs"
TXT_LOG   = DOCS_DIR / "analyzer.txt"
CSV_LOG   = DOCS_DIR / "analyzer.csv"

CSV_HEADERS = [
    "investigation_id", "session_id", "filename", "full_path",
    "event_type", "detection_timestamp", "detection_timezone",
    "original_hash", "previous_hash", "current_hash",
    "file_size_bytes", "username", "hostname", "os_info",
    "local_ips", "mac_addresses", "network_interfaces",
    "notes"
]

STATUS_MATCH    = "MATCH"
STATUS_MISMATCH = "MISMATCH"
STATUS_MISSING  = "MISSING"
STATUS_ERROR    = "ERROR"
STATUS_IDLE     = "IDLE"
STATUS_MONITORING = "MONITORING"

# Colours
CLR_BG        = "#1e1e2e"
CLR_PANEL     = "#2a2a3e"
CLR_ACCENT    = "#7c3aed"
CLR_ACCENT2   = "#06b6d4"
CLR_SUCCESS   = "#22c55e"
CLR_WARNING   = "#f59e0b"
CLR_DANGER    = "#ef4444"
CLR_TEXT      = "#e2e8f0"
CLR_SUBTEXT   = "#94a3b8"
CLR_BORDER    = "#3f3f5a"
CLR_ROW_ODD   = "#252538"
CLR_ROW_EVEN  = "#2a2a3e"

# ─────────────────────────────────────────────────────────────
# Utility helpers
# ─────────────────────────────────────────────────────────────

def ensure_docs():
    """Create docs directory and initialise log files if they don't exist."""
    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    if not TXT_LOG.exists():
        TXT_LOG.write_text(
            f"# {APP_NAME} Forensic Analyzer Log\n"
            f"# Created: {_ts_now()}\n"
            f"# {'=' * 70}\n\n",
            encoding="utf-8"
        )
    if not CSV_LOG.exists():
        with CSV_LOG.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            writer.writeheader()


def _ts_now() -> str:
    """Return current UTC timestamp string with timezone."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _ts_local() -> str:
    """Return current local timestamp string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sha256_file(path: str) -> str | None:
    """Calculate SHA-256 hash of a file. Returns None on failure."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def file_size(path: str) -> int | None:
    """Return file size in bytes or None."""
    try:
        return os.path.getsize(path)
    except Exception:
        return None


def collect_system_info() -> dict:
    """Collect available system and network metadata."""
    info = {}

    # Username
    try:
        info["username"] = getpass.getuser()
    except Exception:
        info["username"] = "unknown"

    # Hostname
    try:
        info["hostname"] = socket.gethostname()
    except Exception:
        info["hostname"] = "unknown"

    # OS info
    try:
        info["os_info"] = f"{platform.system()} {platform.release()} ({platform.version()})"
    except Exception:
        info["os_info"] = "unknown"

    # Network interfaces
    local_ips   = []
    mac_addrs   = []
    iface_lines = []

    if PSUTIL_AVAILABLE:
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET:
                        local_ips.append(addr.address)
                        iface_lines.append(f"{iface}:{addr.address}")
                    if hasattr(psutil, "AF_LINK") and addr.family == psutil.AF_LINK:
                        mac_addrs.append(f"{iface}={addr.address}")
        except Exception:
            pass
    else:
        try:
            local_ips.append(socket.gethostbyname(socket.gethostname()))
        except Exception:
            pass

    info["local_ips"]          = "; ".join(local_ips)  if local_ips   else "unavailable"
    info["mac_addresses"]      = "; ".join(mac_addrs)   if mac_addrs   else "unavailable"
    info["network_interfaces"] = "; ".join(iface_lines) if iface_lines else "unavailable"
    return info


# ─────────────────────────────────────────────────────────────
# Forensic Logger
# ─────────────────────────────────────────────────────────────

class ForensicLogger:
    """Thread-safe writer for TXT and CSV analyzer logs."""

    def __init__(self):
        self._lock = threading.Lock()
        ensure_docs()

    def log_event(self, *, investigation_id: str, session_id: str,
                  filepath: str, event_type: str,
                  original_hash: str | None, previous_hash: str | None,
                  current_hash: str | None, notes: str = ""):
        """Append a forensic event record to both log files."""
        sysinfo = collect_system_info()
        now     = datetime.now(timezone.utc)
        ts_str  = now.strftime("%Y-%m-%d %H:%M:%S")
        tz_str  = now.strftime("%Z")
        fpath   = Path(filepath)
        fsize   = file_size(filepath) if current_hash else None

        row = {
            "investigation_id": investigation_id,
            "session_id":       session_id,
            "filename":         fpath.name,
            "full_path":        str(fpath.resolve()),
            "event_type":       event_type,
            "detection_timestamp": ts_str,
            "detection_timezone":  tz_str,
            "original_hash":    original_hash  or "N/A",
            "previous_hash":    previous_hash  or "N/A",
            "current_hash":     current_hash   or "N/A",
            "file_size_bytes":  str(fsize) if fsize is not None else "N/A",
            "username":         sysinfo["username"],
            "hostname":         sysinfo["hostname"],
            "os_info":          sysinfo["os_info"],
            "local_ips":        sysinfo["local_ips"],
            "mac_addresses":    sysinfo["mac_addresses"],
            "network_interfaces": sysinfo["network_interfaces"],
            "notes":            notes,
        }

        with self._lock:
            self._write_txt(row)
            self._write_csv(row)

    def _write_txt(self, row: dict):
        sep = "─" * 72
        lines = [
            f"\n{sep}",
            f"  Investigation ID : {row['investigation_id']}",
            f"  Session ID       : {row['session_id']}",
            f"  Event            : {row['event_type']}",
            f"  Detection Time   : {row['detection_timestamp']} {row['detection_timezone']}",
            f"  File             : {row['filename']}",
            f"  Full Path        : {row['full_path']}",
            f"  File Size        : {row['file_size_bytes']} bytes",
            f"  Original Hash    : {row['original_hash']}",
            f"  Previous Hash    : {row['previous_hash']}",
            f"  Current Hash     : {row['current_hash']}",
            f"  Username         : {row['username']}",
            f"  Hostname         : {row['hostname']}",
            f"  OS               : {row['os_info']}",
            f"  Local IPs        : {row['local_ips']}",
            f"  MAC Addresses    : {row['mac_addresses']}",
            f"  Interfaces       : {row['network_interfaces']}",
        ]
        if row["notes"]:
            lines.append(f"  Notes            : {row['notes']}")
        lines.append(sep)

        with TXT_LOG.open("a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

    def _write_csv(self, row: dict):
        with CSV_LOG.open("a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            writer.writerow(row)


# ─────────────────────────────────────────────────────────────
# Watchdog Event Handler
# ─────────────────────────────────────────────────────────────

class FileGuardHandler(FileSystemEventHandler):
    """Handles filesystem events for a monitored file."""

    def __init__(self, target_path: str, app_callback):
        super().__init__()
        self._target   = os.path.normcase(os.path.abspath(target_path))
        self._callback = app_callback
        # Paths that should never trigger events (the log files themselves)
        self._excluded = {
            os.path.normcase(str(TXT_LOG.resolve())),
            os.path.normcase(str(CSV_LOG.resolve())),
        }

    def _is_target(self, path: str) -> bool:
        n = os.path.normcase(os.path.abspath(path))
        return n == self._target and n not in self._excluded

    def on_modified(self, event):
        if not event.is_directory and self._is_target(event.src_path):
            self._callback("MODIFIED", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory and self._is_target(event.src_path):
            self._callback("DELETED", event.src_path)

    def on_created(self, event):
        if not event.is_directory and self._is_target(event.src_path):
            self._callback("CREATED", event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            src = os.path.normcase(os.path.abspath(event.src_path))
            dst = os.path.normcase(os.path.abspath(event.dest_path))
            if src == self._target or dst == self._target:
                self._callback("RENAMED/MOVED", event.src_path,
                               extra=event.dest_path)


# ─────────────────────────────────────────────────────────────
# Main Application
# ─────────────────────────────────────────────────────────────

class FileGuardApp:
    """Main FileGuard Tkinter application."""

    def __init__(self, root: tk.Tk):
        self.root    = root
        self.logger  = ForensicLogger()

        # State
        self.session_id       = str(uuid.uuid4())[:8].upper()
        self.investigation_id = None
        self.monitored_path   = None
        self.monitored_folder = None   # folder-level target
        self.original_hash    = None
        self.previous_hash    = None
        self.current_hash     = None
        self.is_monitoring    = False
        self.observer         = None
        self.text_snapshot    = None   # for diff comparison
        self._event_count     = 0
        self._polling_job     = None   # after() id for folder poll
        self._folder_hashes   = {}     # {filepath: hash}

        self._build_gui()
        self._refresh_sysinfo()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── GUI Construction ──────────────────────────────────────

    def _build_gui(self):
        self.root.title(f"{APP_NAME} v{APP_VERSION} — Digital Forensics & Integrity Monitor")
        self.root.geometry("1200x780")
        self.root.minsize(900, 600)
        self.root.configure(bg=CLR_BG)

        # ttk style
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(".",              background=CLR_BG,   foreground=CLR_TEXT,
                        fieldbackground=CLR_PANEL, troughcolor=CLR_PANEL,
                        bordercolor=CLR_BORDER)
        style.configure("TFrame",        background=CLR_BG)
        style.configure("Panel.TFrame",  background=CLR_PANEL, relief="flat")
        style.configure("TLabel",        background=CLR_BG,   foreground=CLR_TEXT,
                        font=("Segoe UI", 9))
        style.configure("Title.TLabel",  background=CLR_BG,   foreground=CLR_TEXT,
                        font=("Segoe UI", 18, "bold"))
        style.configure("Sub.TLabel",    background=CLR_BG,   foreground=CLR_SUBTEXT,
                        font=("Segoe UI", 9))
        style.configure("Head.TLabel",   background=CLR_PANEL, foreground=CLR_ACCENT2,
                        font=("Segoe UI", 9, "bold"))
        style.configure("Val.TLabel",    background=CLR_PANEL, foreground=CLR_TEXT,
                        font=("Consolas", 9))
        style.configure("Status.TLabel", background=CLR_PANEL, foreground=CLR_SUCCESS,
                        font=("Segoe UI", 12, "bold"))
        style.configure("TButton",       background=CLR_ACCENT, foreground="#ffffff",
                        font=("Segoe UI", 9, "bold"), relief="flat", padding=(10, 5))
        style.map("TButton",
                  background=[("active", "#6d28d9"), ("disabled", "#3f3f5a")],
                  foreground=[("disabled", CLR_SUBTEXT)])
        style.configure("Danger.TButton",  background=CLR_DANGER,  foreground="#ffffff",
                        font=("Segoe UI", 9, "bold"), relief="flat", padding=(10, 5))
        style.map("Danger.TButton",
                  background=[("active", "#dc2626"), ("disabled", "#3f3f5a")])
        style.configure("Success.TButton", background=CLR_SUCCESS, foreground="#000000",
                        font=("Segoe UI", 9, "bold"), relief="flat", padding=(10, 5))
        style.map("Success.TButton",
                  background=[("active", "#16a34a"), ("disabled", "#3f3f5a")])
        style.configure("Treeview",       background=CLR_ROW_EVEN, foreground=CLR_TEXT,
                        fieldbackground=CLR_ROW_EVEN, rowheight=24,
                        font=("Consolas", 8))
        style.configure("Treeview.Heading", background=CLR_PANEL, foreground=CLR_ACCENT2,
                        font=("Segoe UI", 9, "bold"), relief="flat")
        style.map("Treeview", background=[("selected", CLR_ACCENT)])
        style.configure("TNotebook",       background=CLR_BG,    tabmargins=[0, 0, 0, 0])
        style.configure("TNotebook.Tab",   background=CLR_PANEL, foreground=CLR_SUBTEXT,
                        padding=(14, 6), font=("Segoe UI", 9))
        style.map("TNotebook.Tab",
                  background=[("selected", CLR_ACCENT)],
                  foreground=[("selected", "#ffffff")])
        style.configure("TScrollbar",      background=CLR_PANEL, troughcolor=CLR_BG,
                        arrowcolor=CLR_SUBTEXT)
        style.configure("TSeparator",      background=CLR_BORDER)
        style.configure("TProgressbar",    troughcolor=CLR_PANEL, background=CLR_ACCENT)
        style.configure("TLabelframe",     background=CLR_PANEL, foreground=CLR_ACCENT2,
                        bordercolor=CLR_BORDER, relief="solid")
        style.configure("TLabelframe.Label", background=CLR_PANEL, foreground=CLR_ACCENT2,
                        font=("Segoe UI", 9, "bold"))

        # ── Header bar ──────────────────────────────────────
        hdr = tk.Frame(self.root, bg=CLR_PANEL, height=56)
        hdr.pack(fill="x", side="top")
        hdr.pack_propagate(False)

        tk.Label(hdr, text="🛡", bg=CLR_PANEL, fg=CLR_ACCENT,
                 font=("Segoe UI", 20)).pack(side="left", padx=(18, 6), pady=8)
        tk.Label(hdr, text=APP_NAME, bg=CLR_PANEL, fg=CLR_TEXT,
                 font=("Segoe UI", 16, "bold")).pack(side="left", pady=8)
        tk.Label(hdr, text="  Digital Forensics & Integrity Monitor",
                 bg=CLR_PANEL, fg=CLR_SUBTEXT,
                 font=("Segoe UI", 9)).pack(side="left", pady=8)

        self._session_lbl = tk.Label(hdr, text=f"Session: {self.session_id}",
                                     bg=CLR_PANEL, fg=CLR_SUBTEXT,
                                     font=("Consolas", 8))
        self._session_lbl.pack(side="right", padx=18)

        self._clock_lbl = tk.Label(hdr, text="", bg=CLR_PANEL, fg=CLR_SUBTEXT,
                                   font=("Consolas", 8))
        self._clock_lbl.pack(side="right", padx=(0, 12))
        self._tick_clock()

        # ── Main paned layout ────────────────────────────────
        main = ttk.PanedWindow(self.root, orient="horizontal")
        main.pack(fill="both", expand=True, padx=8, pady=(6, 4))

        left  = ttk.Frame(main)
        right = ttk.Frame(main)
        main.add(left,  weight=1)
        main.add(right, weight=3)

        self._build_left_panel(left)
        self._build_right_panel(right)

        # ── Status bar ───────────────────────────────────────
        sb = tk.Frame(self.root, bg=CLR_PANEL, height=24)
        sb.pack(fill="x", side="bottom")
        sb.pack_propagate(False)
        self._statusbar_lbl = tk.Label(sb, text="Ready.", bg=CLR_PANEL, fg=CLR_SUBTEXT,
                                       font=("Segoe UI", 8), anchor="w")
        self._statusbar_lbl.pack(side="left", padx=10)
        tk.Label(sb, text=f"{APP_NAME} {APP_VERSION}", bg=CLR_PANEL, fg=CLR_BORDER,
                 font=("Segoe UI", 8)).pack(side="right", padx=10)

    # ── Left panel ────────────────────────────────────────────

    def _build_left_panel(self, parent):
        parent.configure(style="Panel.TFrame")

        # File selection group
        sel_frame = ttk.LabelFrame(parent, text=" Target Selection ", padding=10)
        sel_frame.pack(fill="x", padx=8, pady=(8, 4))

        ttk.Button(sel_frame, text="📄 Select File",
                   command=self._select_file).pack(fill="x", pady=(0, 4))
        ttk.Button(sel_frame, text="📁 Select Folder",
                   command=self._select_folder).pack(fill="x")

        self._target_lbl = tk.Label(sel_frame, text="No target selected",
                                    bg=CLR_PANEL, fg=CLR_SUBTEXT,
                                    font=("Consolas", 7), wraplength=200,
                                    justify="left", anchor="w")
        self._target_lbl.pack(fill="x", pady=(6, 0))

        # Monitoring controls
        ctrl_frame = ttk.LabelFrame(parent, text=" Monitoring ", padding=10)
        ctrl_frame.pack(fill="x", padx=8, pady=4)

        self._start_btn = ttk.Button(ctrl_frame, text="▶ Start Monitoring",
                                     style="Success.TButton",
                                     command=self._start_monitoring,
                                     state="disabled")
        self._start_btn.pack(fill="x", pady=(0, 4))

        self._stop_btn = ttk.Button(ctrl_frame, text="⏹ Stop Monitoring",
                                    style="Danger.TButton",
                                    command=self._stop_monitoring,
                                    state="disabled")
        self._stop_btn.pack(fill="x")

        # Monitoring indicator
        self._mon_status_lbl = tk.Label(ctrl_frame, text="● IDLE",
                                        bg=CLR_PANEL, fg=CLR_SUBTEXT,
                                        font=("Segoe UI", 10, "bold"))
        self._mon_status_lbl.pack(pady=(8, 0))

        # Hash display
        hash_frame = ttk.LabelFrame(parent, text=" Hash Values ", padding=10)
        hash_frame.pack(fill="x", padx=8, pady=4)

        for label_text, attr in [
            ("Original Baseline:", "_orig_hash_lbl"),
            ("Previous Hash:", "_prev_hash_lbl"),
            ("Current Hash:",  "_curr_hash_lbl"),
        ]:
            ttk.Label(hash_frame, text=label_text, style="Head.TLabel").pack(
                anchor="w", pady=(4, 0))
            lbl = tk.Label(hash_frame, text="—",
                           bg=CLR_PANEL, fg=CLR_TEXT,
                           font=("Consolas", 7), wraplength=200,
                           justify="left", anchor="w")
            lbl.pack(fill="x")
            setattr(self, attr, lbl)

        # Integrity status
        int_frame = ttk.LabelFrame(parent, text=" Integrity Status ", padding=10)
        int_frame.pack(fill="x", padx=8, pady=4)

        self._integrity_lbl = tk.Label(int_frame, text=STATUS_IDLE,
                                       bg=CLR_PANEL, fg=CLR_SUBTEXT,
                                       font=("Segoe UI", 14, "bold"))
        self._integrity_lbl.pack(pady=4)

        # Actions
        act_frame = ttk.LabelFrame(parent, text=" Actions ", padding=10)
        act_frame.pack(fill="x", padx=8, pady=4)

        ttk.Button(act_frame, text="🔍 Verify Integrity",
                   command=self._verify_integrity).pack(fill="x", pady=(0, 4))
        ttk.Button(act_frame, text="📊 Open Analyzer",
                   command=self._open_analyzer).pack(fill="x", pady=(0, 4))
        ttk.Button(act_frame, text="💾 Export Report",
                   command=self._export_report).pack(fill="x", pady=(0, 4))
        ttk.Button(act_frame, text="🔎 Compare Text Diff",
                   command=self._compare_diff).pack(fill="x", pady=(0, 4))
        ttk.Button(act_frame, text="📋 Clear Event Table",
                   command=self._clear_table).pack(fill="x")

    # ── Right panel ───────────────────────────────────────────

    def _build_right_panel(self, parent):
        nb = ttk.Notebook(parent)
        nb.pack(fill="both", expand=True, padx=4, pady=4)

        # Tab 1 — Live Events
        events_tab = ttk.Frame(nb)
        nb.add(events_tab, text="  📋 Live Events  ")
        self._build_events_tab(events_tab)

        # Tab 2 — System Info
        sysinfo_tab = ttk.Frame(nb)
        nb.add(sysinfo_tab, text="  🖥 System Info  ")
        self._build_sysinfo_tab(sysinfo_tab)

        # Tab 3 — Analyzer Log
        analyzer_tab = ttk.Frame(nb)
        nb.add(analyzer_tab, text="  📂 Analyzer Log  ")
        self._build_analyzer_tab(analyzer_tab)

        # Tab 4 — Investigation History
        history_tab = ttk.Frame(nb)
        nb.add(history_tab, text="  🕵 History  ")
        self._build_history_tab(history_tab)

    def _build_events_tab(self, parent):
        cols = ("time", "event", "status", "current_hash", "size")
        self._event_tree = ttk.Treeview(parent, columns=cols, show="headings",
                                        selectmode="browse")
        widths = {"time": 155, "event": 130, "status": 90, "current_hash": 340, "size": 80}
        headings = {"time": "Detection Time", "event": "Event Type",
                    "status": "Status", "current_hash": "Current Hash", "size": "Size"}
        for c in cols:
            self._event_tree.heading(c, text=headings[c])
            self._event_tree.column(c, width=widths[c], stretch=(c == "current_hash"))

        self._event_tree.tag_configure("MATCH",    foreground=CLR_SUCCESS)
        self._event_tree.tag_configure("MISMATCH", foreground=CLR_DANGER)
        self._event_tree.tag_configure("MISSING",  foreground=CLR_WARNING)
        self._event_tree.tag_configure("ERROR",    foreground=CLR_SUBTEXT)
        self._event_tree.tag_configure("INFO",     foreground=CLR_ACCENT2)
        self._event_tree.tag_configure("odd",      background=CLR_ROW_ODD)
        self._event_tree.tag_configure("even",     background=CLR_ROW_EVEN)

        vsb = ttk.Scrollbar(parent, orient="vertical",   command=self._event_tree.yview)
        hsb = ttk.Scrollbar(parent, orient="horizontal", command=self._event_tree.xview)
        self._event_tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self._event_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        parent.rowconfigure(0, weight=1)
        parent.columnconfigure(0, weight=1)

    def _build_sysinfo_tab(self, parent):
        frame = ttk.Frame(parent, padding=10)
        frame.pack(fill="both", expand=True)

        self._sysinfo_text = scrolledtext.ScrolledText(
            frame, bg=CLR_PANEL, fg=CLR_TEXT, font=("Consolas", 9),
            relief="flat", wrap="word", state="disabled",
            insertbackground=CLR_TEXT)
        self._sysinfo_text.pack(fill="both", expand=True)

        ttk.Button(frame, text="🔄 Refresh System Info",
                   command=self._refresh_sysinfo).pack(pady=(6, 0))

    def _build_analyzer_tab(self, parent):
        frame = ttk.Frame(parent, padding=6)
        frame.pack(fill="both", expand=True)

        self._analyzer_text = scrolledtext.ScrolledText(
            frame, bg=CLR_PANEL, fg=CLR_TEXT, font=("Consolas", 8),
            relief="flat", wrap="none", state="disabled",
            insertbackground=CLR_TEXT)
        self._analyzer_text.pack(fill="both", expand=True)

        btn_row = ttk.Frame(frame)
        btn_row.pack(fill="x", pady=(6, 0))
        ttk.Button(btn_row, text="🔄 Reload Log",
                   command=self._reload_analyzer).pack(side="left", padx=(0, 4))
        ttk.Button(btn_row, text="📁 Open Log Folder",
                   command=lambda: os.startfile(str(DOCS_DIR))).pack(side="left")

        self._reload_analyzer()

    def _build_history_tab(self, parent):
        frame = ttk.Frame(parent, padding=6)
        frame.pack(fill="both", expand=True)

        cols = ("inv_id", "session", "file", "events", "started")
        self._hist_tree = ttk.Treeview(frame, columns=cols, show="headings",
                                       selectmode="browse")
        for c, h, w in [("inv_id", "Investigation ID", 140),
                        ("session", "Session ID", 80),
                        ("file", "Filename", 200),
                        ("events", "Events", 60),
                        ("started", "First Seen", 155)]:
            self._hist_tree.heading(c, text=h)
            self._hist_tree.column(c, width=w, stretch=(c == "file"))

        vsb = ttk.Scrollbar(frame, orient="vertical",  command=self._hist_tree.yview)
        self._hist_tree.configure(yscrollcommand=vsb.set)
        self._hist_tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)

        ttk.Button(frame, text="🔄 Reload History",
                   command=self._reload_history).grid(row=1, column=0, columnspan=2,
                                                      sticky="w", pady=(6, 0))
        self._reload_history()

    # ── Clock ─────────────────────────────────────────────────

    def _tick_clock(self):
        self._clock_lbl.configure(text=datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.root.after(1000, self._tick_clock)

    # ── File / Folder selection ───────────────────────────────

    def _select_file(self):
        path = filedialog.askopenfilename(title="Select a file to monitor")
        if path:
            self._set_target(path, is_folder=False)

    def _select_folder(self):
        path = filedialog.askdirectory(title="Select a folder to monitor")
        if path:
            self._set_target(path, is_folder=True)

    def _set_target(self, path: str, is_folder: bool):
        if self.is_monitoring:
            messagebox.showwarning("Monitoring Active",
                                   "Stop monitoring before selecting a new target.")
            return

        if is_folder:
            self.monitored_folder = path
            self.monitored_path   = None
        else:
            self.monitored_path   = path
            self.monitored_folder = None

        display = Path(path).name
        self._target_lbl.configure(text=display, fg=CLR_TEXT)
        self._set_status(f"Target: {display}")

        # Compute baseline for a single file
        if not is_folder:
            self._compute_baseline()
        else:
            self._orig_hash_lbl.configure(text="(folder mode)")
            self._prev_hash_lbl.configure(text="—")
            self._curr_hash_lbl.configure(text="—")
            self._integrity_lbl.configure(text=STATUS_IDLE, fg=CLR_SUBTEXT)

        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")

    def _compute_baseline(self):
        if not self.monitored_path:
            return
        h = sha256_file(self.monitored_path)
        if h:
            self.original_hash = h
            self.previous_hash = h
            self.current_hash  = h
            self._orig_hash_lbl.configure(text=h)
            self._prev_hash_lbl.configure(text=h)
            self._curr_hash_lbl.configure(text=h)
            self._integrity_lbl.configure(text=STATUS_MATCH, fg=CLR_SUCCESS)
            # Save text snapshot for diff
            try:
                self.text_snapshot = Path(self.monitored_path).read_text(
                    encoding="utf-8", errors="replace")
            except Exception:
                self.text_snapshot = None
        else:
            self._integrity_lbl.configure(text=STATUS_ERROR, fg=CLR_DANGER)
            self._set_status("ERROR: Could not hash the selected file.")

    # ── Monitoring start / stop ───────────────────────────────

    def _start_monitoring(self):
        if self.is_monitoring:
            return
        if not self.monitored_path and not self.monitored_folder:
            messagebox.showwarning("No Target", "Please select a file or folder first.")
            return
        if not WATCHDOG_AVAILABLE:
            messagebox.showerror("Dependency Missing",
                                 "watchdog is not installed.\n"
                                 "Run: pip install watchdog")
            return

        self.investigation_id = str(uuid.uuid4())
        self.is_monitoring    = True
        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._mon_status_lbl.configure(text="● MONITORING", fg=CLR_SUCCESS)

        if self.monitored_path:
            # Single-file watchdog
            watch_dir = str(Path(self.monitored_path).parent)
            handler   = FileGuardHandler(self.monitored_path, self._on_fs_event)
            self.observer = Observer()
            self.observer.schedule(handler, watch_dir, recursive=False)
            self.observer.start()
            # Log baseline event
            self._log_and_record(
                event_type="MONITORING_STARTED",
                file_path=self.monitored_path,
                current_hash=self.original_hash,
                status_tag="INFO",
                notes="Baseline established. Monitoring started."
            )
        else:
            # Folder mode — build initial snapshot and start polling
            self._init_folder_snapshot()
            watch_dir = self.monitored_folder
            handler   = FileGuardHandler(watch_dir, self._on_folder_fs_event)
            self.observer = Observer()
            self.observer.schedule(handler, watch_dir, recursive=True)
            self.observer.start()
            self._log_and_record(
                event_type="MONITORING_STARTED",
                file_path=self.monitored_folder,
                current_hash=None,
                status_tag="INFO",
                notes=f"Folder monitoring started: {self.monitored_folder}"
            )

        self._set_status("Monitoring active.")
        self._add_event_row(
            time=_ts_local(), event="MONITORING_STARTED",
            status="INFO", hash_val="—", size="—", tag="INFO"
        )

    def _stop_monitoring(self):
        if not self.is_monitoring:
            return
        self.is_monitoring = False
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=3)
            self.observer = None
        if self._polling_job:
            self.root.after_cancel(self._polling_job)
            self._polling_job = None

        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        self._mon_status_lbl.configure(text="● IDLE", fg=CLR_SUBTEXT)

        target = self.monitored_path or self.monitored_folder or "unknown"
        self._log_and_record(
            event_type="MONITORING_STOPPED",
            file_path=target,
            current_hash=self.current_hash,
            status_tag="INFO",
            notes="Monitoring stopped by user."
        )
        self._add_event_row(
            time=_ts_local(), event="MONITORING_STOPPED",
            status="INFO", hash_val="—", size="—", tag="INFO"
        )
        self._set_status("Monitoring stopped.")

    # ── Filesystem event handlers ─────────────────────────────

    def _on_fs_event(self, event_type: str, path: str, extra: str = None):
        """Called from watchdog thread — schedule GUI update on main thread."""
        self.root.after(0, lambda: self._process_file_event(event_type, path, extra))

    def _process_file_event(self, event_type: str, path: str, extra: str = None):
        if not self.is_monitoring:
            return

        new_hash = sha256_file(path) if event_type not in ("DELETED",) else None
        size_val = file_size(path)

        if event_type == "DELETED":
            status   = STATUS_MISSING
            tag      = "MISSING"
            self._integrity_lbl.configure(text=STATUS_MISSING, fg=CLR_WARNING)
        elif new_hash is None:
            status = STATUS_ERROR
            tag    = "ERROR"
            self._integrity_lbl.configure(text=STATUS_ERROR, fg=CLR_SUBTEXT)
        elif new_hash == self.original_hash:
            status = STATUS_MATCH
            tag    = "MATCH"
            self._integrity_lbl.configure(text=STATUS_MATCH, fg=CLR_SUCCESS)
        else:
            status = STATUS_MISMATCH
            tag    = "MISMATCH"
            self._integrity_lbl.configure(text=STATUS_MISMATCH, fg=CLR_DANGER)

        notes = ""
        if extra:
            notes = f"Renamed/moved to: {extra}"

        self._log_and_record(
            event_type=event_type,
            file_path=path,
            current_hash=new_hash,
            status_tag=tag,
            notes=notes
        )

        size_str = str(size_val) if size_val is not None else "N/A"
        self._add_event_row(
            time=_ts_local(),
            event=event_type,
            status=status,
            hash_val=new_hash or "N/A",
            size=size_str,
            tag=tag
        )

        if new_hash:
            self.previous_hash = self.current_hash
            self.current_hash  = new_hash
            self._prev_hash_lbl.configure(text=self.previous_hash or "—")
            self._curr_hash_lbl.configure(text=self.current_hash)

        self._set_status(f"Event: {event_type} — {status}")
        self._reload_analyzer()

    def _init_folder_snapshot(self):
        """Build initial hash snapshot of all files in monitored folder."""
        self._folder_hashes = {}
        base = Path(self.monitored_folder)
        for fp in base.rglob("*"):
            if fp.is_file():
                h = sha256_file(str(fp))
                if h:
                    self._folder_hashes[str(fp)] = h

    def _on_folder_fs_event(self, event_type: str, path: str, extra: str = None):
        self.root.after(0, lambda: self._process_folder_event(event_type, path, extra))

    def _process_folder_event(self, event_type: str, path: str, extra: str = None):
        if not self.is_monitoring:
            return
        # Skip analyzer logs
        normed = os.path.normcase(os.path.abspath(path))
        excluded = {
            os.path.normcase(str(TXT_LOG.resolve())),
            os.path.normcase(str(CSV_LOG.resolve())),
        }
        if normed in excluded:
            return

        new_hash = sha256_file(path) if event_type not in ("DELETED",) else None
        prev_h   = self._folder_hashes.get(path)
        size_val = file_size(path)

        if event_type == "DELETED":
            status = STATUS_MISSING
            tag    = "MISSING"
            self._folder_hashes.pop(path, None)
        elif new_hash is None:
            status = STATUS_ERROR
            tag    = "ERROR"
        elif prev_h and new_hash != prev_h:
            status = STATUS_MISMATCH
            tag    = "MISMATCH"
            self._folder_hashes[path] = new_hash
        else:
            status = STATUS_MATCH
            tag    = "MATCH"
            self._folder_hashes[path] = new_hash

        notes = (f"Renamed/moved to: {extra}" if extra else "")
        self._log_and_record(
            event_type=event_type,
            file_path=path,
            current_hash=new_hash,
            status_tag=tag,
            notes=notes
        )
        size_str = str(size_val) if size_val is not None else "N/A"
        self._add_event_row(
            time=_ts_local(),
            event=f"{event_type} [{Path(path).name}]",
            status=status,
            hash_val=new_hash or "N/A",
            size=size_str,
            tag=tag
        )
        self._set_status(f"Folder event: {event_type} — {Path(path).name}")
        self._reload_analyzer()

    # ── Logging helper ────────────────────────────────────────

    def _log_and_record(self, *, event_type: str, file_path: str,
                        current_hash: str | None, status_tag: str, notes: str = ""):
        self.logger.log_event(
            investigation_id=self.investigation_id or "N/A",
            session_id=self.session_id,
            filepath=file_path,
            event_type=event_type,
            original_hash=self.original_hash,
            previous_hash=self.previous_hash,
            current_hash=current_hash,
            notes=notes
        )

    # ── Event table ───────────────────────────────────────────

    def _add_event_row(self, *, time: str, event: str, status: str,
                       hash_val: str, size: str, tag: str):
        self._event_count += 1
        row_tag = "odd" if self._event_count % 2 else "even"
        self._event_tree.insert(
            "", "end",
            values=(time, event, status, hash_val, size),
            tags=(tag, row_tag)
        )
        # Scroll to bottom
        children = self._event_tree.get_children()
        if children:
            self._event_tree.see(children[-1])

    def _clear_table(self):
        for item in self._event_tree.get_children():
            self._event_tree.delete(item)
        self._event_count = 0

    # ── System info tab ───────────────────────────────────────

    def _refresh_sysinfo(self):
        info = collect_system_info()
        text = (
            f"  Session ID       : {self.session_id}\n"
            f"  Username         : {info['username']}\n"
            f"  Hostname         : {info['hostname']}\n"
            f"  OS               : {info['os_info']}\n"
            f"  Python           : {sys.version.split()[0]}\n"
            f"  Local IPs        : {info['local_ips']}\n"
            f"  MAC Addresses    : {info['mac_addresses']}\n"
            f"  Network Ifaces   : {info['network_interfaces']}\n"
            f"  Watchdog         : {'available' if WATCHDOG_AVAILABLE else 'NOT INSTALLED'}\n"
            f"  psutil           : {'available' if PSUTIL_AVAILABLE else 'NOT INSTALLED'}\n"
            f"  Analyzer TXT     : {TXT_LOG}\n"
            f"  Analyzer CSV     : {CSV_LOG}\n"
            f"  Refreshed        : {_ts_local()}\n"
        )
        self._sysinfo_text.configure(state="normal")
        self._sysinfo_text.delete("1.0", "end")
        self._sysinfo_text.insert("1.0", text)
        self._sysinfo_text.configure(state="disabled")

    # ── Analyzer log tab ──────────────────────────────────────

    def _reload_analyzer(self):
        try:
            content = TXT_LOG.read_text(encoding="utf-8") if TXT_LOG.exists() else "(log not created yet)"
        except Exception as e:
            content = f"Error reading log: {e}"
        self._analyzer_text.configure(state="normal")
        self._analyzer_text.delete("1.0", "end")
        self._analyzer_text.insert("1.0", content)
        self._analyzer_text.see("end")
        self._analyzer_text.configure(state="disabled")

    # ── History tab ───────────────────────────────────────────

    def _reload_history(self):
        for item in self._hist_tree.get_children():
            self._hist_tree.delete(item)

        if not CSV_LOG.exists():
            return
        investigations: dict[str, dict] = {}
        try:
            with CSV_LOG.open(newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    inv = row.get("investigation_id", "")
                    if not inv or inv == "investigation_id":
                        continue
                    if inv not in investigations:
                        investigations[inv] = {
                            "session":  row.get("session_id", ""),
                            "file":     row.get("filename", ""),
                            "events":   0,
                            "started":  row.get("detection_timestamp", ""),
                        }
                    investigations[inv]["events"] += 1
        except Exception:
            pass

        for inv_id, data in investigations.items():
            self._hist_tree.insert("", "end", values=(
                inv_id,
                data["session"],
                data["file"],
                data["events"],
                data["started"],
            ))

    # ── Action buttons ────────────────────────────────────────

    def _verify_integrity(self):
        if not self.monitored_path:
            messagebox.showinfo("No File", "Select a single file target first.")
            return
        if not Path(self.monitored_path).exists():
            messagebox.showwarning("File Missing",
                                   f"The monitored file no longer exists:\n{self.monitored_path}")
            self._integrity_lbl.configure(text=STATUS_MISSING, fg=CLR_WARNING)
            return

        live_hash = sha256_file(self.monitored_path)
        if live_hash is None:
            messagebox.showerror("Error", "Could not compute hash for the file.")
            return

        self.current_hash = live_hash
        self._curr_hash_lbl.configure(text=live_hash)

        if live_hash == self.original_hash:
            status  = STATUS_MATCH
            colour  = CLR_SUCCESS
            msg     = "✅ INTEGRITY VERIFIED\n\nThe file matches its original baseline hash."
        else:
            status  = STATUS_MISMATCH
            colour  = CLR_DANGER
            msg     = ("⚠️ INTEGRITY MISMATCH\n\n"
                       f"Original : {self.original_hash}\n"
                       f"Current  : {live_hash}\n\n"
                       "The file content has changed since monitoring began.")

        self._integrity_lbl.configure(text=status, fg=colour)
        messagebox.showinfo("Integrity Verification", msg)

        self._log_and_record(
            event_type="MANUAL_VERIFY",
            file_path=self.monitored_path,
            current_hash=live_hash,
            status_tag=status,
            notes=f"Manual verification: {status}"
        )
        self._add_event_row(
            time=_ts_local(), event="MANUAL_VERIFY",
            status=status, hash_val=live_hash,
            size=str(file_size(self.monitored_path) or "N/A"),
            tag=status
        )
        self._reload_analyzer()

    def _open_analyzer(self):
        """Open the analyzer TXT log in the default text editor."""
        ensure_docs()
        try:
            os.startfile(str(TXT_LOG))
        except Exception as e:
            messagebox.showerror("Error", f"Could not open analyzer log:\n{e}")

    def _export_report(self):
        """Copy the CSV log to a user-specified location."""
        if not CSV_LOG.exists():
            messagebox.showinfo("No Data", "No analyzer CSV log exists yet.")
            return
        dest = filedialog.asksaveasfilename(
            title="Export Forensic Report",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialfile=f"fileguard_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        if dest:
            try:
                import shutil
                shutil.copy2(str(CSV_LOG), dest)
                messagebox.showinfo("Export Complete",
                                    f"Report exported to:\n{dest}")
            except Exception as e:
                messagebox.showerror("Export Failed", str(e))

    def _compare_diff(self):
        """Compare current file text content against the saved snapshot."""
        if not self.monitored_path:
            messagebox.showinfo("No File", "Select a file target first.")
            return
        if self.text_snapshot is None:
            messagebox.showinfo("No Snapshot",
                                "No text snapshot available. "
                                "Select the file before starting monitoring to capture one.")
            return
        try:
            current_text = Path(self.monitored_path).read_text(
                encoding="utf-8", errors="replace")
        except Exception as e:
            messagebox.showerror("Read Error", str(e))
            return

        diff_lines = list(difflib.unified_diff(
            self.text_snapshot.splitlines(keepends=True),
            current_text.splitlines(keepends=True),
            fromfile="Original (baseline)",
            tofile="Current",
            lineterm=""
        ))

        win = tk.Toplevel(self.root)
        win.title("Text Diff — Baseline vs Current")
        win.geometry("800x500")
        win.configure(bg=CLR_BG)

        txt = scrolledtext.ScrolledText(win, bg=CLR_PANEL, fg=CLR_TEXT,
                                        font=("Consolas", 9), wrap="none")
        txt.pack(fill="both", expand=True, padx=10, pady=10)
        txt.tag_configure("add", foreground=CLR_SUCCESS)
        txt.tag_configure("rem", foreground=CLR_DANGER)
        txt.tag_configure("hdr", foreground=CLR_ACCENT2)

        if not diff_lines:
            txt.insert("end", "No text differences found.\n")
        else:
            for line in diff_lines:
                if line.startswith("+"):
                    txt.insert("end", line + "\n", "add")
                elif line.startswith("-"):
                    txt.insert("end", line + "\n", "rem")
                elif line.startswith("@"):
                    txt.insert("end", line + "\n", "hdr")
                else:
                    txt.insert("end", line + "\n")
        txt.configure(state="disabled")

    # ── Utilities ─────────────────────────────────────────────

    def _set_status(self, msg: str):
        self._statusbar_lbl.configure(text=msg)

    def _on_close(self):
        if self.is_monitoring:
            if messagebox.askyesno("Monitoring Active",
                                   "Monitoring is still running.\nStop and exit?"):
                self._stop_monitoring()
            else:
                return
        self.root.destroy()


# ─────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────

def main():
    ensure_docs()
    root = tk.Tk()
    app  = FileGuardApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
