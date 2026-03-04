import socket
import ssl
import datetime
import time
import os
import json
from struct import pack
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
from tkinter import ttk
import threading
import random
import re
import queue

CONFIG_FILE = "payShield_Command_Sender_Config.json"
DEBUG_LOG_FILE = "debug_packets.log"
BASE_SOCKET_TIMEOUT = 10

# Pre-compile regex used in hot path
_HEX_INLINE_RE = re.compile(r'<(.*?)>')

# Safety-net poll interval: also fires every frame even when quiet
_IDLE_POLL_MS = 16   # ~1 frame @ 60 Hz


class TLSClientGUI:
    def __init__(self, master):
        self.master = master
        master.title("Payshield Command Sender 3.2")

        self.style = ttk.Style()
        self.style.theme_use('clam')

        self.config = self.load_config()

        master.configure(bg="#e0e0e0")
        master.rowconfigure(12, weight=1)
        master.columnconfigure(1, weight=1)

        # -- Style Configuration --
        self.style.configure('TLabel', font=("Segoe UI", 10))
        self.style.configure('TEntry', font=("Segoe UI", 10))
        self.style.configure('TCombobox', font=("Segoe UI", 10))
        self.style.configure('TRadiobutton', font=("Segoe UI", 10))
        self.style.configure('TCheckbutton', font=("Segoe UI", 10))
        self.style.configure('TButton', font=("Segoe UI", 10))
        self.style.configure('Bold.TLabel', font=("Segoe UI", 10, "bold"))
        self.style.configure('Accent.TButton', background='#4CAF50', foreground='white',
                              font=('Segoe UI', 10, 'bold'))
        self.style.map('Accent.TButton', background=[('active', '#45a049')])

        # -- Variables --
        self.protocol_var = tk.StringVar(value=self.config.get("protocol", "TCP"))
        self.tls_var = tk.BooleanVar(value=self.config.get("use_tls", True))
        self.hide_responses_var = tk.BooleanVar(value=self.config.get("hide_responses", False))
        self.show_sent_hex_var = tk.BooleanVar(value=self.config.get("show_sent_hex", False))
        self.persistent_connection_var = tk.BooleanVar(
            value=self.config.get("persistent_connection", True))
        self.debug_mode_var = tk.BooleanVar(value=self.config.get("debug_mode", False))
        self.log_history_limit_var = tk.StringVar(
            value=str(self.config.get("log_history_limit", 500)))
        self.random_delay_var = tk.BooleanVar(
            value=self.config.get("enable_random_delay", False))
        self.max_random_delay_var = tk.StringVar(
            value=str(self.config.get("max_random_delay", 0.1)))
        self.use_secondary_var = tk.BooleanVar(value=self.config.get("use_secondary", False))
        self.result_log_var = tk.BooleanVar(value=self.config.get("enable_result_log", False))
        self.result_log_path_var = tk.StringVar(value=self.config.get("result_log_path", ""))

        # -- UI Components --
        self._init_ui(master)

        # -- Internal State --
        self.running = False
        self.log_queue = queue.Queue()
        self.random_colors_active = False

        self.total_expected_sends = 0
        self.actual_completed_sends = 0
        self.successful_sends = 0
        self.error_sends = 0

        self.stats_lock = threading.Lock()
        self.cps_values = []
        self.responses_received = 0
        self.cps_last_time = None
        self.cps_last_count = 0

        self.color_map = {
            "CONN_CHECK": "#6c757d", "CONN_OK": "green", "CONN_FAIL": "red",
            "ERROR": "red", "SUMMARY_GLOBAL": "#d62728",
            "SUCCESS_RESPONSE": "#007bff", "ERROR_RESPONSE_CODE": "red"
        }

        # Cache for tag configs already applied to the output widget
        self._configured_tags: set = set()

        # Open file handle for result logging (None when disabled)
        self._result_log_file = None
        self._result_log_lock = threading.Lock()

        # Worker threads set this flag then schedule after(0) so the main thread
        # flushes immediately — without waiting for the next timer tick.
        self._flush_scheduled = False

        self.toggle_command_fields()
        self.toggle_secondary_fields()

        # Kick off the safety-net poll loop (catches anything the event missed)
        self.master.after(_IDLE_POLL_MS, self._poll_flush)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _init_ui(self, master):
        # --- Primary Target ---
        frame_pri = ttk.LabelFrame(master, text="Primary Target")
        frame_pri.grid(row=0, column=0, columnspan=3, sticky="ew", padx=10, pady=5)
        frame_pri.columnconfigure(1, weight=1)

        ttk.Label(frame_pri, text="Host:").grid(
            row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.host_history = self.config.get("host_history", [])
        self.host_entry = ttk.Combobox(frame_pri, values=self.host_history)
        self.host_entry.set(self.config.get("host", "192.168.0.31"))
        self.host_entry.grid(row=0, column=1, sticky="ew", padx=5, pady=5)

        ttk.Label(frame_pri, text="Port:").grid(
            row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.port_entry = ttk.Entry(frame_pri, width=10)
        self.port_entry.insert(0, self.config.get("port", "2500"))
        self.port_entry.grid(row=0, column=3, sticky="ew", padx=5, pady=5)

        # --- Secondary Target ---
        frame_sec = ttk.LabelFrame(master, text="Secondary Target")
        frame_sec.grid(row=1, column=0, columnspan=3, sticky="ew", padx=10, pady=5)
        frame_sec.columnconfigure(1, weight=1)

        self.sec_check = ttk.Checkbutton(
            frame_sec, text="Enable Secondary Target",
            variable=self.use_secondary_var, command=self.toggle_secondary_fields)
        self.sec_check.grid(row=0, column=0, columnspan=4, sticky=tk.W, padx=5, pady=(0, 5))

        ttk.Label(frame_sec, text="Host:").grid(
            row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.host_entry_2 = ttk.Combobox(frame_sec, values=self.host_history)
        self.host_entry_2.set(self.config.get("host_2", ""))
        self.host_entry_2.grid(row=1, column=1, sticky="ew", padx=5, pady=5)

        ttk.Label(frame_sec, text="Port:").grid(
            row=1, column=2, sticky=tk.W, padx=5, pady=5)
        self.port_entry_2 = ttk.Entry(frame_sec, width=10)
        self.port_entry_2.insert(0, self.config.get("port_2", ""))
        self.port_entry_2.grid(row=1, column=3, sticky="ew", padx=5, pady=5)

        # --- Command Mode ---
        self.command_mode = tk.StringVar(value=self.config.get("command_mode", "ASCII"))
        ttk.Radiobutton(master, text="Command (ASCII):",
                        variable=self.command_mode, value="ASCII",
                        command=self.toggle_command_fields).grid(
                            row=2, column=0, sticky=tk.W, padx=10, pady=5)
        self.command_entry = scrolledtext.ScrolledText(
            master, wrap=tk.WORD, height=4, font=("Segoe UI", 10))
        self.command_entry.insert(tk.END, self.config.get("command", "NC").strip())
        self.command_entry.grid(row=2, column=1, columnspan=2, sticky="ew", padx=10, pady=5)

        ttk.Radiobutton(master, text="Command (HEX):",
                        variable=self.command_mode, value="HEX",
                        command=self.toggle_command_fields).grid(
                            row=3, column=0, sticky=tk.W, padx=10, pady=5)
        self.hex_command_entry = ttk.Entry(master, state=tk.DISABLED)
        self.hex_command_entry.insert(0, self.config.get("hex_command", ""))
        self.hex_command_entry.grid(row=3, column=1, columnspan=2, sticky="ew", padx=10, pady=5)

        # --- Settings ---
        frame_sets = ttk.Frame(master)
        frame_sets.grid(row=4, column=0, columnspan=3, sticky="ew", padx=10, pady=5)

        ttk.Label(frame_sets, text="Connections (per target):").pack(side=tk.LEFT, padx=5)
        self.conn_count_entry = ttk.Entry(frame_sets, width=10)
        self.conn_count_entry.insert(0, str(self.config.get("connections", 1)))
        self.conn_count_entry.pack(side=tk.LEFT, padx=5)

        ttk.Label(frame_sets, text="Repeat Sends:").pack(side=tk.LEFT, padx=5)
        self.repeat_count_entry = ttk.Entry(frame_sets, width=10)
        self.repeat_count_entry.insert(0, str(self.config.get("repeat_sends", 1)))
        self.repeat_count_entry.pack(side=tk.LEFT, padx=5)

        # --- Stats ---
        self.sends_completed_var = tk.StringVar(value="Sends: 0/0")
        ttk.Label(master, textvariable=self.sends_completed_var,
                  style='Bold.TLabel').grid(row=6, column=0, sticky=tk.W, padx=10, pady=5)
        self.cps_var = tk.StringVar(value="CPS: N/A")
        ttk.Label(master, textvariable=self.cps_var,
                  style='Bold.TLabel').grid(row=6, column=1, sticky=tk.W, padx=10, pady=5)

        # --- Certificates ---
        self._create_file_entry(master, "CA Cert:", 7, "ca_cert")
        self._create_file_entry(master, "Client Key:", 8, "client_key")
        self._create_file_entry(master, "Client Cert:", 9, "client_cert")

        # --- Result Log File ---
        frame_rlog = ttk.Frame(master)
        frame_rlog.grid(row=10, column=0, columnspan=3, sticky="ew", padx=10, pady=(4, 0))
        frame_rlog.columnconfigure(1, weight=1)
        self.result_log_check = ttk.Checkbutton(
            frame_rlog, text="Log results to file:",
            variable=self.result_log_var, command=self._toggle_result_log_path)
        self.result_log_check.grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.result_log_path_entry = ttk.Entry(
            frame_rlog, textvariable=self.result_log_path_var)
        self.result_log_path_entry.grid(row=0, column=1, sticky="ew", padx=(0, 5))
        self.result_log_browse_btn = ttk.Button(
            frame_rlog, text="Browse…", command=self._browse_result_log)
        self.result_log_browse_btn.grid(row=0, column=2)

        # --- Buttons ---
        bf = ttk.Frame(master)
        bf.grid(row=11, column=0, columnspan=3, pady=10, padx=10)
        self.run_button = ttk.Button(bf, text="Run", style='Accent.TButton')
        self.run_button.bind("<Button-1>", self.on_run_button_click)
        self.run_button.pack(side=tk.LEFT, padx=(0, 10))
        self.check_conn_button = ttk.Button(
            bf, text="Check Pri Connection", command=self.start_check_connection_thread)
        self.check_conn_button.pack(side=tk.LEFT, padx=10)
        ttk.Button(bf, text="Stop", command=self.stop_tls_loop).pack(side=tk.LEFT, padx=10)
        self.copy_button = ttk.Button(
            bf, text="Copy Log", command=self.copy_log_to_clipboard)
        self.copy_button.pack(side=tk.LEFT, padx=10)
        ttk.Button(bf, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT, padx=10)
        ttk.Button(bf, text="Options", command=self.open_options_window).pack(
            side=tk.LEFT, padx=10)

        # --- Output ---
        master.rowconfigure(12, weight=1)
        self.output = scrolledtext.ScrolledText(
            master, wrap=tk.WORD, font=("Consolas", 10),
            bg="#f5f5f5", fg="#333333", relief=tk.FLAT, bd=2)
        self.output.grid(row=12, column=0, columnspan=3, sticky="nsew", padx=10, pady=10)

    def _create_file_entry(self, master, label, row, config_key):
        ttk.Label(master, text=label).grid(row=row, column=0, sticky=tk.W, padx=10, pady=5)
        entry = ttk.Entry(master)
        entry.insert(0, self.config.get(config_key, ""))
        entry.grid(row=row, column=1, sticky="ew", padx=10, pady=5)
        ttk.Button(master, text="Browse",
                   command=lambda: self.browse_file(entry)).grid(
                       row=row, column=2, padx=5, pady=5)
        if config_key == "ca_cert":       self.ca_entry = entry
        elif config_key == "client_key":  self.key_entry = entry
        elif config_key == "client_cert": self.cert_entry = entry

    def toggle_secondary_fields(self):
        state = tk.NORMAL if self.use_secondary_var.get() else tk.DISABLED
        self.host_entry_2.config(state=state)
        self.port_entry_2.config(state=state)

    def _toggle_result_log_path(self):
        """Enable/disable path entry and browse button to match the checkbox state."""
        state = tk.NORMAL if self.result_log_var.get() else tk.DISABLED
        self.result_log_path_entry.config(state=state)
        self.result_log_browse_btn.config(state=state)

    def _browse_result_log(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("Log files", "*.log"), ("All files", "*.*")],
            title="Choose result log file"
        )
        if path:
            self.result_log_path_var.set(path)

    # ------------------------------------------------------------------
    # Result file logging
    # ------------------------------------------------------------------

    def _open_result_log(self):
        """
        Open the result log file and write the full session header.
        The header lists every configuration value and enabled option so the
        file is self-contained without needing to cross-reference the UI.
        Called once at the start of each Run.
        """
        if not self.result_log_var.get():
            return
        path = self.result_log_path_var.get().strip()
        if not path:
            self.log("[RESULT LOG] No file path configured — file logging disabled.", "ERROR")
            self.result_log_var.set(False)
            return
        try:
            self._result_log_file = open(path, "a", encoding="utf-8")
            self._write_result_log(self._build_session_header())
            self.log(f"[RESULT LOG] Logging to: {path}", "CONN_OK")
        except Exception as e:
            self.log(f"[RESULT LOG] Could not open file: {e}", "ERROR")
            self._result_log_file = None

    def _close_result_log(self):
        """Flush, write a closing divider, and close the result log file."""
        with self._result_log_lock:
            if self._result_log_file:
                try:
                    self._result_log_file.write("\n" + "=" * 72 + "\n\n")
                    self._result_log_file.flush()
                    self._result_log_file.close()
                except Exception:
                    pass
                self._result_log_file = None

    def _write_result_log(self, text: str):
        """Thread-safe append of a single text block to the result log file."""
        with self._result_log_lock:
            if self._result_log_file:
                try:
                    self._result_log_file.write(text + "\n")
                    self._result_log_file.flush()
                except Exception:
                    pass

    def _build_session_header(self) -> str:
        """
        Return a formatted plaintext block describing the full session
        configuration: targets, network settings, TLS certs, send parameters,
        and every option flag — written at the top of each log session.
        """
        ts   = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        sep  = "=" * 72
        thin = "-" * 72
        protocol = self.protocol_var.get()
        use_tls  = self.tls_var.get() and protocol == "TCP"
        yn = lambda v: "yes" if v else "no"

        lines = [
            sep,
            "  payShield Command Sender \u2014 Session Log",
            f"  Started : {ts}",
            sep,
            "",
            "  TARGETS",
            thin,
            f"  Primary   : {self.host_entry.get()}:{self.port_entry.get()}",
        ]
        if self.use_secondary_var.get():
            lines.append(
                f"  Secondary : {self.host_entry_2.get()}:{self.port_entry_2.get()}")
        else:
            lines.append("  Secondary : disabled")

        lines += [
            "",
            "  NETWORK",
            thin,
            f"  Protocol            : {protocol}",
            f"  TLS                 : {'enabled' if use_tls else 'disabled'}",
            f"  Persistent conn     : {yn(self.persistent_connection_var.get())} (TCP only)",
        ]
        if use_tls:
            lines += [
                f"  CA Cert             : {self.ca_entry.get() or '(none)'}",
                f"  Client Key          : {self.key_entry.get() or '(none)'}",
                f"  Client Cert         : {self.cert_entry.get() or '(none)'}",
            ]

        lines += [
            "",
            "  SEND PARAMETERS",
            thin,
            f"  Connections/target  : {self.conn_count_entry.get()}",
            f"  Repeat sends        : {self.repeat_count_entry.get()}",
            f"  Command mode        : {self.command_mode.get()}",
        ]
        if self.command_mode.get() == "ASCII":
            cmd_text = self.command_entry.get("1.0", tk.END).strip().replace("\n", " | ")
            lines.append(f"  Command             : {cmd_text}")
        else:
            lines.append(f"  Command (hex)       : {self.hex_command_entry.get()}")

        lines += [
            "",
            "  OPTIONS",
            thin,
            f"  Hide responses      : {yn(self.hide_responses_var.get())}",
            f"  Show sent hex       : {yn(self.show_sent_hex_var.get())}",
            f"  Debug mode          : {yn(self.debug_mode_var.get())}",
            f"  Random delay        : {yn(self.random_delay_var.get())}",
        ]
        if self.random_delay_var.get():
            lines.append(f"  Max random delay    : {self.max_random_delay_var.get()} s")

        lines += [
            "",
            "  SESSION RESULTS",
            thin,
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Real-time log flushing
    # Two entry points:
    #   1. _poll_flush  — safety-net timer, fires every _IDLE_POLL_MS (~16 ms)
    #   2. log()        — worker threads call after(0, _do_flush) immediately
    #                     after queuing a message so the UI wakes without delay
    # ------------------------------------------------------------------

    def _poll_flush(self):
        """Safety-net: ensures the UI drains even if an after(0) was missed."""
        self._do_flush()
        self.master.after(_IDLE_POLL_MS, self._poll_flush)

    def _do_flush(self):
        """
        Drain the entire log queue and refresh stats labels in one Tk call.
        Always called on the main thread.
        """
        self._flush_scheduled = False

        try:
            limit = max(int(self.log_history_limit_var.get()), 50)
        except ValueError:
            limit = 500

        get_nowait = self.log_queue.get_nowait
        insert = self.output.insert
        tag_config = self.output.tag_config
        configured = self._configured_tags
        hide = self.hide_responses_var.get()
        _visible = {"SUMMARY_GLOBAL", "ERROR", "CONN_OK", "CONN_FAIL", "CONN_CHECK",
                    "SUCCESS_RESPONSE", "ERROR_RESPONSE_CODE"}

        batch = []
        try:
            while True:
                message, tag, color = get_nowait()
                if hide and tag not in _visible:
                    continue
                if tag not in configured:
                    tag_config(tag, foreground=color)
                    configured.add(tag)
                batch.append((message, tag))
        except queue.Empty:
            pass

        if batch:
            for message, tag in batch:
                insert(tk.END, message + '\n', tag)
            current_lines = int(self.output.index('end-1c').split('.')[0])
            if current_lines > limit:
                self.output.delete('1.0', f'{current_lines - limit + 1}.0')
            self.output.see(tk.END)

        # Refresh the send-counter every flush pass — no separate after() needed
        if self.running:
            self.sends_completed_var.set(
                f"Sends: {self.actual_completed_sends}/{self.total_expected_sends}")

    def log(self, message, tag=None):
        safe_tag = tag if tag else "INFO"
        color = self.color_map.get(safe_tag)
        if color is None:
            color = (f"#{random.randint(0, 0xFFFFFF):06x}"
                     if self.random_colors_active else "#333333")
        self.log_queue.put((message, safe_tag, color))
        # Mirror to result log file (thread-safe; no-op when file logging is disabled)
        self._write_result_log(message)
        # Schedule an immediate flush on the main thread if one isn't already pending
        if not self._flush_scheduled:
            self._flush_scheduled = True
            self.master.after(0, self._do_flush)

    # ------------------------------------------------------------------
    # SSL / command preparation
    # ------------------------------------------------------------------

    def get_ssl_context(self):
        if not self.tls_var.get() or self.protocol_var.get() == "UDP":
            return None
        try:
            context = ssl.create_default_context(cafile=self.ca_entry.get() or None)
            try:
                context.verify_flags &= ~ssl.VERIFY_X509_STRICT
            except AttributeError:
                pass
            context.check_hostname = False
            context.verify_mode = ssl.CERT_REQUIRED
            if self.key_entry.get() and self.cert_entry.get():
                context.load_cert_chain(keyfile=self.key_entry.get(),
                                        certfile=self.cert_entry.get())
            return context
        except Exception as e:
            self.log(f"[ERROR] SSL Setup Failed: {e}", "ERROR")
            return None

    def _prepare_commands(self):
        cmds = []
        try:
            if self.command_mode.get() == "ASCII":
                raw_lines = [c.strip() for c in
                             self.command_entry.get("1.0", tk.END).splitlines() if c.strip()]
                for line in raw_lines:
                    processed = _HEX_INLINE_RE.sub(
                        lambda m: m.group(1).encode('utf-8').hex().upper(), line)
                    payload = ('HEAD' + processed).encode('utf-8')
                    cmds.append(pack('>h', len(payload)) + payload)
            else:
                hex_str = self.hex_command_entry.get().replace(" ", "").replace("\n", "")
                if len(hex_str) % 2 != 0:
                    raise ValueError("Odd length hex string")
                payload = b'HEAD' + bytes.fromhex(hex_str)
                cmds.append(pack('>h', len(payload)) + payload)
        except Exception as e:
            messagebox.showerror("Command Error", f"Failed to parse commands: {e}")
            return None
        return cmds

    # ------------------------------------------------------------------
    # Run / worker management
    # ------------------------------------------------------------------

    def start_tls_thread(self):
        if self.running:
            return

        commands_bytes = self._prepare_commands()
        if not commands_bytes:
            return

        try:
            connections = int(self.conn_count_entry.get())
            repeats = int(self.repeat_count_entry.get())
            if connections <= 0 or repeats <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Input Error",
                                 "Connections and repeats must be positive integers.")
            return

        targets = [{"host": self.host_entry.get(),
                    "port": int(self.port_entry.get()),
                    "label": "Pri"}]

        if self.use_secondary_var.get():
            try:
                sec_host = self.host_entry_2.get()
                sec_port = int(self.port_entry_2.get())
                if not sec_host:
                    raise ValueError("Host empty")
                targets.append({"host": sec_host, "port": sec_port, "label": "Sec"})
            except ValueError:
                messagebox.showerror("Input Error", "Secondary Host/Port invalid.")
                return

        if self.debug_mode_var.get():
            connections = 1
            repeats = 1
            commands_bytes = commands_bytes[:1]
            self.log("[DEBUG MODE] Active. 1 Connection/Repeat per target.", "INFO")

        self.save_config()

        self.running = True
        self.actual_completed_sends = 0
        self.successful_sends = 0
        self.error_sends = 0
        self.total_expected_sends = (len(targets) * connections
                                     * repeats * len(commands_bytes))
        self.sends_completed_var.set(f"Sends: 0/{self.total_expected_sends}")

        with self.stats_lock:
            self.cps_values = []
            self.responses_received = 0
            self.cps_last_time = time.time()
            self.cps_last_count = 0

        ssl_context = self.get_ssl_context()
        if self.protocol_var.get() == "TCP" and self.tls_var.get() and not ssl_context:
            self.running = False
            return

        # CPS refreshes every 250 ms — 4× more current than the original 1 s
        self.master.after(250, self.update_cps_display)

        self._open_result_log()

        threading.Thread(
            target=self.run_workers,
            args=(targets, connections, repeats, commands_bytes, ssl_context),
            daemon=True
        ).start()

    def run_workers(self, targets, connections, repeats, commands_bytes, ssl_context):
        threads = []
        total_threads = len(targets) * connections
        semaphore = threading.Semaphore(total_threads)

        for target_info in targets:
            for i in range(1, connections + 1):
                if not self.running:
                    break
                t = threading.Thread(
                    target=self._worker_logic,
                    args=(i, target_info, repeats, commands_bytes, ssl_context, semaphore),
                    daemon=True
                )
                threads.append(t)
                t.start()

        for t in threads:
            t.join()

        self.running = False
        self._close_result_log()
        # after(0) so the final summary lands immediately on the main thread
        self.master.after(0, self._log_final_summary)

    def _worker_logic(self, thread_id, target_info, repeats, commands_bytes,
                      ssl_context, semaphore):
        semaphore.acquire()
        try:
            host = target_info['host']
            port = target_info['port']
            label = target_info['label']

            protocol = self.protocol_var.get()
            is_persistent = self.persistent_connection_var.get()
            use_tls = self.tls_var.get()
            timeout = self.get_adjusted_timeout()
            # Snapshot delay settings once per worker to avoid repeated StringVar reads
            use_random_delay = self.random_delay_var.get()
            try:
                max_delay = float(self.max_random_delay_var.get()) if use_random_delay else 0.0
            except ValueError:
                max_delay = 0.0

            tag = f"T{thread_id}-{label}"
            sock = None

            for r in range(repeats):
                if not self.running:
                    break

                if protocol == "TCP":
                    if sock is None:
                        try:
                            raw_sock = socket.create_connection((host, port), timeout=timeout)
                            raw_sock.settimeout(timeout)
                            if use_tls and ssl_context:
                                sock = ssl_context.wrap_socket(raw_sock, server_hostname=host)
                            else:
                                sock = raw_sock
                            if not is_persistent:
                                self.log(
                                    f"[{tag}] Connected {host}:{port} (Repeat {r+1})", tag)
                        except Exception as e:
                            self.log(f"[{tag}] Connect Error {host}: {e}", "ERROR")
                            with self.stats_lock:
                                self.error_sends += 1
                            continue

                    for cmd_bytes in commands_bytes:
                        if not self.running:
                            break
                        if use_random_delay:
                            time.sleep(random.uniform(0, max_delay))
                        try:
                            if self.debug_mode_var.get():
                                self._debug_log(cmd_bytes, f"SENT-TCP-{label}")
                            start_time = time.time()
                            sock.sendall(cmd_bytes)
                            response = sock.recv(4096)
                            rtt = time.time() - start_time
                            self._handle_response(response, rtt, tag, label, cmd_bytes)
                        except Exception as e:
                            self.log(f"[{tag}] IO Error: {e}", "ERROR")
                            with self.stats_lock:
                                self.error_sends += 1
                            if sock:
                                try: sock.close()
                                except: pass
                            sock = None
                            break

                    if not is_persistent and sock:
                        try: sock.close()
                        except: pass
                        sock = None

                else:  # UDP
                    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    udp_sock.settimeout(timeout)
                    try:
                        for cmd_bytes in commands_bytes:
                            if not self.running:
                                break
                            if use_random_delay:
                                time.sleep(random.uniform(0, max_delay))
                            try:
                                if self.debug_mode_var.get():
                                    self._debug_log(cmd_bytes, f"SENT-UDP-{label}")
                                start_time = time.time()
                                udp_sock.sendto(cmd_bytes, (host, port))
                                response, _ = udp_sock.recvfrom(4096)
                                rtt = time.time() - start_time
                                self._handle_response(response, rtt, tag, label, cmd_bytes)
                            except socket.timeout:
                                self.log(f"[{tag}] UDP Timeout {host}:{port}", "ERROR")
                                with self.stats_lock:
                                    self.error_sends += 1
                            except Exception as e:
                                self.log(f"[{tag}] UDP Error: {e}", "ERROR")
                                with self.stats_lock:
                                    self.error_sends += 1
                    finally:
                        udp_sock.close()

            if sock:
                try: sock.close()
                except: pass

        except Exception as e:
            self.log(f"[{tag}] Fatal Error: {e}", "ERROR")
        finally:
            semaphore.release()

    # ------------------------------------------------------------------
    # Response handling & stats
    # ------------------------------------------------------------------

    def _handle_response(self, response, rtt, tag, label, cmd_bytes):
        if self.debug_mode_var.get():
            self._debug_log(response, f"RECV-{label}")

        with self.stats_lock:
            self.responses_received += 1
            self.actual_completed_sends += 1

            if not response:
                self.error_sends += 1
                self.log(f"[{tag}] Empty response", "ERROR")
                return

            is_success = len(response) >= 10 and response[8:10] == b'00'
            if is_success:
                self.successful_sends += 1
                log_tag = "SUCCESS_RESPONSE"
            else:
                self.error_sends += 1
                log_tag = "ERROR_RESPONSE_CODE"

        if self.show_sent_hex_var.get():
            self.log(f"[{tag}] SENT:\n{self.format_hex_stream(cmd_bytes)}", tag)

        # log() triggers an immediate after(0) flush, which also updates the
        # send-counter label — no separate after() call from the worker needed.
        self.log(f"[{tag}] RECV (RTT: {rtt:.3f}s):\n{self.format_hex_stream(response)}",
                 log_tag)

    def _debug_log(self, data, direction):
        try:
            with open(DEBUG_LOG_FILE, "a") as f:
                f.write(f"\n--- {direction} PACKET ({datetime.datetime.now()}) ---\n")
                f.write(self.format_hex_stream(data) + "\n--- END PACKET ---\n")
        except:
            pass

    def _log_final_summary(self):
        self.log(
            f"\n[SUMMARY] Success: {self.successful_sends}, "
            f"Errors: {self.error_sends} (Total: {self.actual_completed_sends})",
            "SUMMARY_GLOBAL"
        )
        with self.stats_lock:
            if self.cps_values:
                avg = sum(self.cps_values) / len(self.cps_values)
                self.log(f"[SUMMARY] Avg CPS: {avg:.2f}", "SUMMARY_GLOBAL")
        self.sends_completed_var.set(
            f"Sends: {self.actual_completed_sends}/{self.total_expected_sends}")

    def update_progress_gui(self):
        # Send-counter is now refreshed on every _do_flush pass.
        # Method kept for API/subclass compatibility.
        pass

    def get_adjusted_timeout(self):
        to = BASE_SOCKET_TIMEOUT
        if self.random_delay_var.get():
            try:
                to += float(self.max_random_delay_var.get())
            except:
                pass
        return to

    @staticmethod
    def format_hex_stream(data, bytes_per_line=16):
        """Format bytes as a hex + ASCII dump. Static to avoid self lookup overhead."""
        if not data:
            return ""
        hex_lines = []
        width = bytes_per_line * 3
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i + bytes_per_line]
            hex_part = ' '.join(f'{b:02X}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            hex_lines.append(f"{hex_part:<{width}}  {ascii_part}")
        return "\n".join(hex_lines)

    def update_cps_display(self):
        """Refresh the CPS label every 250 ms — 4× more current than before."""
        if not self.running:
            return
        with self.stats_lock:
            now = time.time()
            elapsed = now - self.cps_last_time
            if elapsed >= 0.25:
                count = self.responses_received - self.cps_last_count
                cps = count / elapsed
                self.cps_values.append(cps)
                avg = sum(self.cps_values) / len(self.cps_values)
                self.cps_var.set(f"CPS: {cps:.2f} (Avg: {avg:.2f})")
                self.cps_last_time = now
                self.cps_last_count = self.responses_received
        self.master.after(250, self.update_cps_display)

    # ------------------------------------------------------------------
    # Connection check
    # ------------------------------------------------------------------

    def start_check_connection_thread(self):
        self.check_conn_button.config(state=tk.DISABLED)
        threading.Thread(target=self.check_connection, daemon=True).start()

    def check_connection(self):
        host = self.host_entry.get()
        protocol = self.protocol_var.get()
        try:
            port = int(self.port_entry.get())
            timeout = self.get_adjusted_timeout()
            self.log(
                f"[CONN_CHECK] Checking Primary {host}:{port} via {protocol}...",
                "CONN_CHECK")

            msg = ('HEAD' + 'NC').encode('utf-8')
            full_msg = pack('>h', len(msg)) + msg

            if protocol == "TCP":
                ctx = self.get_ssl_context()
                with socket.create_connection((host, port), timeout=timeout) as s:
                    if ctx:
                        s = ctx.wrap_socket(s, server_hostname=host)
                    s.sendall(full_msg)
                    resp = s.recv(1024)
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(timeout)
                    s.sendto(full_msg, (host, port))
                    resp, _ = s.recvfrom(1024)

            if resp and b'ND00' in resp:
                fw = resp[-9:].decode('ascii', errors='ignore') if len(resp) >= 9 else "?"
                self.log(f"[CONN_CHECK] Success. Firmware: {fw}", "CONN_OK")
            else:
                self.log(f"[CONN_CHECK] Received invalid/empty response.", "CONN_FAIL")
        except Exception as e:
            self.log(f"[CONN_CHECK] Failed: {e}", "CONN_FAIL")
        finally:
            self.master.after(0, lambda: self.check_conn_button.config(state=tk.NORMAL))

    # ------------------------------------------------------------------
    # UI helpers / toggles
    # ------------------------------------------------------------------

    def toggle_command_fields(self):
        if self.command_mode.get() == "ASCII":
            self.command_entry.config(state=tk.NORMAL, bg="white")
            self.hex_command_entry.config(state=tk.DISABLED)
        else:
            self.command_entry.config(state=tk.DISABLED, bg="#f0f0f0")
            self.hex_command_entry.config(state=tk.NORMAL)

    def update_port_based_on_protocol(self):
        if self.protocol_var.get() == "UDP":
            default_port = "1500"
        else:
            default_port = "2500" if self.tls_var.get() else "1500"
        self.port_entry.delete(0, tk.END)
        self.port_entry.insert(0, default_port)
        if self.use_secondary_var.get():
            self.port_entry_2.delete(0, tk.END)
            self.port_entry_2.insert(0, default_port)

    def browse_file(self, entry):
        path = filedialog.askopenfilename()
        if path:
            entry.delete(0, tk.END)
            entry.insert(0, path)

    def copy_log_to_clipboard(self):
        self.master.clipboard_clear()
        self.master.clipboard_append(self.output.get(1.0, tk.END))
        self.copy_button.config(text="Copied!")
        self.master.after(2000, lambda: self.copy_button.config(text="Copy Log"))

    def clear_log(self):
        self.output.delete(1.0, tk.END)
        self._configured_tags.clear()
        self.sends_completed_var.set("Sends: 0/0")
        with self.stats_lock:
            self.successful_sends = 0
            self.error_sends = 0
            self.actual_completed_sends = 0
            self.cps_values.clear()
        self.cps_var.set("CPS: N/A")

    def on_run_button_click(self, event):
        self.random_colors_active = bool(event.state & 0x4)
        self.start_tls_thread()

    def stop_tls_loop(self):
        self.running = False

    # ------------------------------------------------------------------
    # Config persistence
    # ------------------------------------------------------------------

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r") as f:
                    return json.load(f)
            except:
                pass
        return {}

    def save_config(self):
        try:
            hist = list(self.host_history)
            for h in (self.host_entry.get(), self.host_entry_2.get()):
                if h and h not in hist:
                    hist.insert(0, h)
            seen: set = set()
            unique_hist = []
            for h in hist:
                if h not in seen:
                    unique_hist.append(h)
                    seen.add(h)
            hist = unique_hist[:10]

            config = {
                "host": self.host_entry.get(),
                "host_history": hist,
                "port": self.port_entry.get(),
                "host_2": self.host_entry_2.get(),
                "port_2": self.port_entry_2.get(),
                "use_secondary": self.use_secondary_var.get(),
                "command_mode": self.command_mode.get(),
                "command": self.command_entry.get("1.0", tk.END).strip(),
                "hex_command": self.hex_command_entry.get(),
                "protocol": self.protocol_var.get(),
                "use_tls": self.tls_var.get(),
                "connections": int(self.conn_count_entry.get()),
                "repeat_sends": int(self.repeat_count_entry.get()),
                "ca_cert": self.ca_entry.get(),
                "client_key": self.key_entry.get(),
                "client_cert": self.cert_entry.get(),
                "hide_responses": self.hide_responses_var.get(),
                "show_sent_hex": self.show_sent_hex_var.get(),
                "persistent_connection": self.persistent_connection_var.get(),
                "debug_mode": self.debug_mode_var.get(),
                "log_history_limit": int(self.log_history_limit_var.get()),
                "enable_random_delay": self.random_delay_var.get(),
                "max_random_delay": self.max_random_delay_var.get(),
                "enable_result_log": self.result_log_var.get(),
                "result_log_path": self.result_log_path_var.get(),
            }
            with open(CONFIG_FILE, "w") as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            print(f"Save config failed: {e}")

    # ------------------------------------------------------------------
    # Options window
    # ------------------------------------------------------------------

    def open_options_window(self):
        top = tk.Toplevel(self.master)
        top.title("Options")
        top.geometry("420x550")
        top.configure(bg="#e0e0e0")

        ttk.Label(top, text="Protocol:", style='Bold.TLabel').pack(
            anchor=tk.W, padx=10, pady=(10, 0))
        ttk.Radiobutton(top, text="TCP", variable=self.protocol_var, value="TCP",
                        command=self.update_port_based_on_protocol).pack(
                            anchor=tk.W, padx=20)
        ttk.Radiobutton(top, text="UDP", variable=self.protocol_var, value="UDP",
                        command=self.update_port_based_on_protocol).pack(
                            anchor=tk.W, padx=20)

        ttk.Checkbutton(top, text="Use TLS (TCP Only)", variable=self.tls_var,
                        command=self.update_port_based_on_protocol).pack(
                            anchor=tk.W, padx=10, pady=5)
        ttk.Checkbutton(top, text="Hide Responses (Errors Only)",
                        variable=self.hide_responses_var).pack(anchor=tk.W, padx=10, pady=5)
        ttk.Checkbutton(top, text="Show Sent Data (Hex)",
                        variable=self.show_sent_hex_var).pack(anchor=tk.W, padx=10, pady=5)
        ttk.Checkbutton(top, text="Maintain Persistent Connection (TCP Only)",
                        variable=self.persistent_connection_var).pack(
                            anchor=tk.W, padx=10, pady=5)
        ttk.Checkbutton(top, text="Enable Debug Mode (Log to file)",
                        variable=self.debug_mode_var).pack(anchor=tk.W, padx=10, pady=5)

        ttk.Label(top, text="Log Lines Limit:").pack(anchor=tk.W, padx=10, pady=2)
        ttk.Entry(top, textvariable=self.log_history_limit_var).pack(
            fill=tk.X, padx=10, pady=2)

        ttk.Checkbutton(top, text="Random Pre-Send Delay",
                        variable=self.random_delay_var).pack(anchor=tk.W, padx=10, pady=5)
        ttk.Label(top, text="Max Delay (s):").pack(anchor=tk.W, padx=10, pady=2)
        ttk.Entry(top, textvariable=self.max_random_delay_var).pack(
            fill=tk.X, padx=10, pady=2)

        ttk.Button(top, text="Close", command=top.destroy).pack(pady=20)


if __name__ == "__main__":
    root = tk.Tk()
    app = TLSClientGUI(root)
    root.mainloop()