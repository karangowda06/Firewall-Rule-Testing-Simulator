"""
╔══════════════════════════════════════════════════════════╗
║        FIREWALL RULE TESTING SIMULATOR - CYBER RANGE     ║
║        Final Year Cybersecurity Project                   ║
╚══════════════════════════════════════════════════════════╝
Author  : Cyber Range Toolkit
Version : 2.0 (Fixed Toggle Logic + Full Feature Set)
"""

import tkinter as tk
from tkinter import ttk, messagebox
import random
import time
import threading


# ─────────────────────────────────────────────────────────────
#  CONSTANTS & THEME
# ─────────────────────────────────────────────────────────────

BG_DEEP    = "#0a0f1e"   # deepest background
BG_PANEL   = "#0f172a"   # main panels
BG_CARD    = "#1e293b"   # card / form surface
BG_ROW_A   = "#1a2540"   # table row alternating A
BG_ROW_B   = "#1e293b"   # table row alternating B

FG_WHITE   = "#f1f5f9"
FG_GREY    = "#94a3b8"
FG_DIM     = "#475569"

CLR_GREEN  = "#22c55e"
CLR_RED    = "#ef4444"
CLR_BLUE   = "#38bdf8"
CLR_AMBER  = "#f59e0b"
CLR_PURPLE = "#a78bfa"
CLR_TEAL   = "#2dd4bf"

FONT_MONO  = ("Courier New", 10)
FONT_LABEL = ("Consolas", 10)
FONT_TITLE = ("Consolas", 13, "bold")
FONT_STATS = ("Consolas", 12, "bold")

PROTOCOLS  = ["ANY", "TCP", "UDP", "ICMP", "HTTP", "HTTPS", "FTP", "DNS"]

# Common + attack-like ports for realistic simulation
COMMON_PORTS   = [80, 443, 53, 8080, 8443]
ATTACK_PORTS   = [22, 23, 21, 3389, 4444, 1337, 31337]
ALL_PORTS      = COMMON_PORTS + ATTACK_PORTS


# ─────────────────────────────────────────────────────────────
#  FIREWALL ENGINE
# ─────────────────────────────────────────────────────────────

class Firewall:
    """
    Stateful firewall engine.
    Rules are evaluated in insertion order (first match wins).
    Default policy: DENY.
    """

    def __init__(self):
        self.rules: list[dict] = []

    # ── Rule Management ──────────────────────────────────────

    def add_rule(self, src: str, dest: str, port, protocol: str, action: str) -> dict:
        """Append a rule and return it (with auto-assigned priority index)."""
        rule = {
            "src":      src,
            "dest":     dest,
            "port":     port,          # int or "ANY"
            "protocol": protocol,
            "action":   action,
        }
        self.rules.append(rule)
        return rule

    def remove_rule(self, index: int) -> bool:
        """Remove rule by list index; returns True on success."""
        if 0 <= index < len(self.rules):
            self.rules.pop(index)
            return True
        return False

    def clear_rules(self):
        self.rules.clear()

    # ── Packet Evaluation ────────────────────────────────────

    def check_packet(self, packet: dict) -> tuple[str, int]:
        """
        Evaluate packet against ordered rule list.
        Returns (action, matched_rule_index) or ("DENY", -1) for default deny.
        """
        for i, rule in enumerate(self.rules):
            if self._match(rule, packet):
                return rule["action"], i
        return "DENY", -1   # default-deny policy

    @staticmethod
    def _match(rule: dict, packet: dict) -> bool:
        """Check whether a single rule matches a packet field-by-field."""
        src_ok      = (rule["src"]      == "ANY" or rule["src"]      == packet["src"])
        dest_ok     = (rule["dest"]     == "ANY" or rule["dest"]     == packet["dest"])
        port_ok     = (rule["port"]     == "ANY" or rule["port"]     == packet["port"])
        protocol_ok = (rule["protocol"] == "ANY" or rule["protocol"] == packet["protocol"])
        return src_ok and dest_ok and port_ok and protocol_ok


# ─────────────────────────────────────────────────────────────
#  PACKET GENERATOR
# ─────────────────────────────────────────────────────────────

class PacketGenerator:
    """Generates realistic (and attacker-style) test packets."""

    INTERNAL_RANGES = [
        "192.168.1.{}",
        "10.0.0.{}",
        "172.16.0.{}",
    ]
    EXTERNAL_IPS = [
        "45.33.32.156",   # known scanner IP (Shodan)
        "198.51.100.{}",
        "203.0.113.{}",
        "185.220.101.{}",
    ]

    @classmethod
    def generate(cls) -> dict:
        # 30 % chance of "attack-like" packet (external IP, suspicious port)
        if random.random() < 0.30:
            template = random.choice(cls.EXTERNAL_IPS)
            src = template.format(random.randint(1, 254)) if "{}" in template else template
            port = random.choice(ATTACK_PORTS)
        else:
            src = random.choice(cls.INTERNAL_RANGES).format(random.randint(1, 200))
            port = random.choice(COMMON_PORTS)

        dest_template = random.choice(cls.INTERNAL_RANGES)
        dest = dest_template.format(random.randint(1, 10))

        return {
            "src":      src,
            "dest":     dest,
            "port":     port,
            "protocol": random.choice(PROTOCOLS[1:]),   # skip "ANY"
        }


# ─────────────────────────────────────────────────────────────
#  TOOLTIP HELPER
# ─────────────────────────────────────────────────────────────

class ToolTip:
    """Simple hover tooltip."""
    def __init__(self, widget, text):
        self.widget = widget
        self.text   = text
        self.tip    = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, _=None):
        x = self.widget.winfo_rootx() + 20
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 4
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.geometry(f"+{x}+{y}")
        tk.Label(
            self.tip, text=self.text,
            bg="#1e293b", fg=FG_GREY,
            font=("Consolas", 9), padx=6, pady=3,
            relief="flat", bd=0
        ).pack()

    def hide(self, _=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


# ─────────────────────────────────────────────────────────────
#  MAIN APPLICATION
# ─────────────────────────────────────────────────────────────

class FirewallApp:
    """
    Main application class.
    Owns the Firewall engine and the entire Tkinter UI.
    """

    def __init__(self, root: tk.Tk):
        self.root     = root
        self.firewall = Firewall()
        self.running  = False
        self.allowed  = 0
        self.denied   = 0
        self._sim_job = None   # after() handle

        self._configure_root()
        self._apply_ttk_style()
        self._build_ui()

    # ── Window / Style Setup ─────────────────────────────────

    def _configure_root(self):
        self.root.title("⚡ Firewall Rule Testing Simulator  |  Cyber Range v2.0")
        self.root.geometry("1200x800")
        self.root.minsize(900, 650)
        self.root.configure(bg=BG_DEEP)
        try:
            self.root.state("zoomed")          # maximise on Windows
        except tk.TclError:
            pass

    def _apply_ttk_style(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")

        # Combobox
        style.configure(
            "Dark.TCombobox",
            fieldbackground=BG_CARD,
            background=BG_CARD,
            foreground=FG_WHITE,
            selectbackground=BG_CARD,
            selectforeground=FG_WHITE,
            bordercolor=FG_DIM,
            arrowcolor=CLR_BLUE,
        )
        style.map("Dark.TCombobox",
                  fieldbackground=[("readonly", BG_CARD)],
                  foreground=[("readonly", FG_WHITE)])

        # Treeview (rule table)
        style.configure(
            "Rules.Treeview",
            background=BG_ROW_B,
            fieldbackground=BG_ROW_B,
            foreground=FG_WHITE,
            rowheight=26,
            font=FONT_MONO,
            borderwidth=0,
        )
        style.configure(
            "Rules.Treeview.Heading",
            background=BG_CARD,
            foreground=CLR_BLUE,
            font=("Consolas", 10, "bold"),
            relief="flat",
        )
        style.map("Rules.Treeview",
                  background=[("selected", "#2d3f5e")],
                  foreground=[("selected", FG_WHITE)])

        # Scrollbar
        style.configure(
            "Dark.Vertical.TScrollbar",
            background=BG_CARD,
            troughcolor=BG_PANEL,
            arrowcolor=FG_DIM,
            bordercolor=BG_PANEL,
        )

    # ── UI Construction ──────────────────────────────────────

    def _build_ui(self):
        """Assemble the full window layout."""

        # ── Title bar ────────────────────────────────────────
        title_bar = tk.Frame(self.root, bg=BG_DEEP)
        title_bar.pack(fill="x", padx=0, pady=(10, 4))

        tk.Label(
            title_bar,
            text="⚡ FIREWALL RULE TESTING SIMULATOR",
            bg=BG_DEEP, fg=CLR_BLUE,
            font=("Consolas", 16, "bold"),
        ).pack(side="left", padx=20)

        tk.Label(
            title_bar,
            text="CYBER RANGE  //  FIRST-MATCH / DEFAULT-DENY",
            bg=BG_DEEP, fg=FG_DIM,
            font=("Consolas", 10),
        ).pack(side="right", padx=20)

        separator = tk.Frame(self.root, bg=CLR_BLUE, height=1)
        separator.pack(fill="x", padx=20, pady=(0, 8))

        # ── Main layout: left column | right column ──────────
        body = tk.Frame(self.root, bg=BG_DEEP)
        body.pack(fill="both", expand=True, padx=16, pady=(0, 12))

        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)
        body.rowconfigure(0, weight=0)
        body.rowconfigure(1, weight=1)

        # ── Left top: Rule Builder ────────────────────────────
        self._build_rule_form(body)

        # ── Left bottom: Rule Table ───────────────────────────
        self._build_rule_table(body)

        # ── Right: Log + Stats ────────────────────────────────
        self._build_right_panel(body)

    # ─── Rule Builder Form ───────────────────────────────────

    def _build_rule_form(self, parent):
        card = tk.Frame(parent, bg=BG_CARD, bd=0)
        card.grid(row=0, column=0, sticky="ew", padx=(0, 8), pady=(0, 8))

        tk.Label(card, text="▸ ADD FIREWALL RULE",
                 bg=BG_CARD, fg=CLR_TEAL,
                 font=FONT_TITLE).grid(
            row=0, column=0, columnspan=12, sticky="w", padx=12, pady=(10, 6))

        # ─── Source IP ───────────────────────────────────────
        self._src_any = tk.BooleanVar(value=True)
        self._src_entry, _ = self._labeled_field_with_any(
            card, col=0, label="Source IP",
            any_var=self._src_any,
            placeholder="e.g. 192.168.1.10",
            tooltip="Source IP address of the packet, or ANY to match all."
        )

        # ─── Destination IP ──────────────────────────────────
        self._dest_any = tk.BooleanVar(value=True)
        self._dest_entry, _ = self._labeled_field_with_any(
            card, col=2, label="Destination IP",
            any_var=self._dest_any,
            placeholder="e.g. 10.0.0.1",
            tooltip="Destination IP address, or ANY to match all."
        )

        # ─── Port ────────────────────────────────────────────
        self._port_any = tk.BooleanVar(value=True)
        self._port_spin, _ = self._labeled_spinbox_with_any(
            card, col=4, label="Port",
            any_var=self._port_any,
            tooltip="Destination port (1–65535), or ANY."
        )

        # ─── Protocol ────────────────────────────────────────
        tk.Label(card, text="Protocol",
                 bg=BG_CARD, fg=FG_GREY,
                 font=FONT_LABEL).grid(row=1, column=6, sticky="w", padx=(14, 4))
        self._protocol_cb = ttk.Combobox(
            card, values=PROTOCOLS, width=9,
            style="Dark.TCombobox", state="readonly"
        )
        self._protocol_cb.set("ANY")
        self._protocol_cb.grid(row=2, column=6, padx=(14, 4), pady=(0, 10))

        # ─── Action ──────────────────────────────────────────
        tk.Label(card, text="Action",
                 bg=BG_CARD, fg=FG_GREY,
                 font=FONT_LABEL).grid(row=1, column=7, sticky="w", padx=(8, 4))
        self._action_cb = ttk.Combobox(
            card, values=["ALLOW", "DENY"], width=8,
            style="Dark.TCombobox", state="readonly"
        )
        self._action_cb.set("ALLOW")
        self._action_cb.grid(row=2, column=7, padx=(8, 4), pady=(0, 10))

        # ─── Add Rule Button ──────────────────────────────────
        tk.Button(
            card, text="＋ Add Rule",
            bg=CLR_GREEN, fg="#000",
            font=("Consolas", 10, "bold"),
            relief="flat", cursor="hand2",
            command=self._on_add_rule, padx=10
        ).grid(row=2, column=8, padx=(12, 12), pady=(0, 10), sticky="w")

    def _labeled_field_with_any(self, parent, col, label, any_var, placeholder, tooltip):
        """
        Build a label + ANY-checkbox + Entry triplet.
        Trace the BooleanVar so the Entry is automatically enabled/disabled.
        Returns (entry_widget, any_checkbutton).
        """
        tk.Label(parent, text=label,
                 bg=BG_CARD, fg=FG_GREY,
                 font=FONT_LABEL).grid(row=1, column=col, sticky="w", padx=(14, 0))

        entry = tk.Entry(
            parent,
            bg="#0f172a", fg=FG_WHITE, insertbackground=FG_WHITE,
            disabledbackground="#0d1525", disabledforeground=FG_DIM,
            font=FONT_MONO, relief="flat", width=16,
            highlightthickness=1,
            highlightcolor=CLR_BLUE,
            highlightbackground=FG_DIM,
        )
        entry.insert(0, placeholder)
        entry.grid(row=2, column=col, padx=(14, 0), pady=(0, 10), sticky="w")
        ToolTip(entry, tooltip)

        chk = tk.Checkbutton(
            parent, text="ANY",
            variable=any_var,
            bg=BG_CARD, fg=CLR_AMBER,
            selectcolor=BG_CARD,
            activebackground=BG_CARD, activeforeground=CLR_AMBER,
            font=("Consolas", 9, "bold"),
        )
        chk.grid(row=1, column=col + 1, sticky="w", padx=4, pady=(6, 0))

        # ── CRITICAL TOGGLE LOGIC ────────────────────────────
        # Trace fires whenever the BooleanVar changes (checkbox toggled).
        def _sync_state(*_):
            if any_var.get():
                entry.config(state="disabled")
            else:
                entry.config(state="normal")
                entry.focus_set()

        any_var.trace_add("write", _sync_state)
        _sync_state()          # apply initial state immediately

        return entry, chk

    def _labeled_spinbox_with_any(self, parent, col, label, any_var, tooltip):
        """
        Build a label + ANY-checkbox + Spinbox triplet for numeric port input.
        """
        tk.Label(parent, text=label,
                 bg=BG_CARD, fg=FG_GREY,
                 font=FONT_LABEL).grid(row=1, column=col, sticky="w", padx=(14, 0))

        spin = tk.Spinbox(
            parent,
            from_=1, to=65535, width=8,
            bg="#0f172a", fg=FG_WHITE, insertbackground=FG_WHITE,
            disabledbackground="#0d1525", disabledforeground=FG_DIM,
            buttonbackground=BG_CARD,
            font=FONT_MONO, relief="flat",
            highlightthickness=1,
            highlightcolor=CLR_BLUE,
            highlightbackground=FG_DIM,
        )
        spin.delete(0, "end")
        spin.insert(0, "80")
        spin.grid(row=2, column=col, padx=(14, 0), pady=(0, 10), sticky="w")
        ToolTip(spin, tooltip)

        chk = tk.Checkbutton(
            parent, text="ANY",
            variable=any_var,
            bg=BG_CARD, fg=CLR_AMBER,
            selectcolor=BG_CARD,
            activebackground=BG_CARD, activeforeground=CLR_AMBER,
            font=("Consolas", 9, "bold"),
        )
        chk.grid(row=1, column=col + 1, sticky="w", padx=4, pady=(6, 0))

        # ── CRITICAL TOGGLE LOGIC ────────────────────────────
        def _sync_state(*_):
            if any_var.get():
                spin.config(state="disabled")
            else:
                spin.config(state="normal")
                spin.focus_set()

        any_var.trace_add("write", _sync_state)
        _sync_state()

        return spin, chk

    # ─── Rule Table ──────────────────────────────────────────

    def _build_rule_table(self, parent):
        frame = tk.Frame(parent, bg=BG_PANEL)
        frame.grid(row=1, column=0, sticky="nsew", padx=(0, 8), pady=0)
        frame.rowconfigure(1, weight=1)
        frame.columnconfigure(0, weight=1)

        # Header row
        hdr = tk.Frame(frame, bg=BG_PANEL)
        hdr.grid(row=0, column=0, columnspan=2, sticky="ew")

        tk.Label(hdr, text="▸ ACTIVE RULES  (highest priority → lowest)",
                 bg=BG_PANEL, fg=CLR_TEAL,
                 font=FONT_TITLE).pack(side="left", padx=12, pady=(8, 4))

        btn_frame = tk.Frame(hdr, bg=BG_PANEL)
        btn_frame.pack(side="right", padx=8)

        tk.Button(
            btn_frame, text="✕ Remove Selected",
            bg="#7f1d1d", fg=FG_WHITE,
            font=("Consolas", 9), relief="flat", cursor="hand2",
            command=self._on_remove_rule, padx=6, pady=2
        ).pack(side="left", padx=4)

        tk.Button(
            btn_frame, text="⬛ Clear All Rules",
            bg=FG_DIM, fg=FG_WHITE,
            font=("Consolas", 9), relief="flat", cursor="hand2",
            command=self._on_clear_rules, padx=6, pady=2
        ).pack(side="left", padx=4)

        # Treeview
        cols = ("#", "Source IP", "Dest IP", "Port", "Protocol", "Action")
        self._tree = ttk.Treeview(
            frame, columns=cols, show="headings",
            style="Rules.Treeview", selectmode="browse"
        )

        col_widths = [30, 130, 130, 60, 90, 80]
        for c, w in zip(cols, col_widths):
            self._tree.heading(c, text=c)
            self._tree.column(c, width=w, anchor="center", stretch=(c not in ("#", "Port")))

        self._tree.tag_configure("allow", foreground=CLR_GREEN)
        self._tree.tag_configure("deny",  foreground=CLR_RED)
        self._tree.tag_configure("odd",   background=BG_ROW_A)
        self._tree.tag_configure("even",  background=BG_ROW_B)

        vsb = ttk.Scrollbar(frame, orient="vertical",
                            command=self._tree.yview,
                            style="Dark.Vertical.TScrollbar")
        self._tree.configure(yscrollcommand=vsb.set)

        self._tree.grid(row=1, column=0, sticky="nsew", padx=(12, 0), pady=(0, 10))
        vsb.grid(row=1, column=1, sticky="ns", pady=(0, 10), padx=(0, 4))

        # Empty-state label
        self._empty_label = tk.Label(
            frame,
            text="No rules yet.  Add a rule above ↑",
            bg=BG_PANEL, fg=FG_DIM, font=("Consolas", 11)
        )
        self._empty_label.grid(row=1, column=0, columnspan=2, pady=30)

    # ─── Right Panel (Log + Controls + Stats) ────────────────

    def _build_right_panel(self, parent):
        right = tk.Frame(parent, bg=BG_PANEL)
        right.grid(row=0, column=1, rowspan=2, sticky="nsew")
        right.rowconfigure(2, weight=1)
        right.columnconfigure(0, weight=1)

        # ── Stats bar ────────────────────────────────────────
        stats_bar = tk.Frame(right, bg=BG_CARD)
        stats_bar.grid(row=0, column=0, sticky="ew", padx=0, pady=(0, 8))

        self._lbl_allowed = tk.Label(
            stats_bar, text="✔ ALLOWED:  0",
            bg=BG_CARD, fg=CLR_GREEN, font=FONT_STATS
        )
        self._lbl_allowed.pack(side="left", padx=20, pady=8)

        self._lbl_denied = tk.Label(
            stats_bar, text="✘ DENIED:  0",
            bg=BG_CARD, fg=CLR_RED, font=FONT_STATS
        )
        self._lbl_denied.pack(side="left", padx=20, pady=8)

        self._lbl_total = tk.Label(
            stats_bar, text="TOTAL:  0",
            bg=BG_CARD, fg=FG_GREY, font=FONT_STATS
        )
        self._lbl_total.pack(side="left", padx=20, pady=8)

        self._lbl_status = tk.Label(
            stats_bar, text="● IDLE",
            bg=BG_CARD, fg=FG_DIM, font=("Consolas", 11, "bold")
        )
        self._lbl_status.pack(side="right", padx=20, pady=8)

        # ── Simulation controls ───────────────────────────────
        ctrl = tk.Frame(right, bg=BG_PANEL)
        ctrl.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 8))

        tk.Label(ctrl, text="▸ SIMULATION CONTROLS",
                 bg=BG_PANEL, fg=CLR_TEAL,
                 font=FONT_TITLE).pack(side="left")

        btn_cfg = [
            ("▶  Start", CLR_BLUE,   "#000", self._on_start),
            ("■  Stop",  CLR_RED,    "#000", self._on_stop),
            ("🗑  Clear Log", FG_DIM, FG_WHITE, self._on_clear_log),
        ]
        for txt, bg, fg, cmd in btn_cfg:
            tk.Button(
                ctrl, text=txt,
                bg=bg, fg=fg,
                font=("Consolas", 10, "bold"),
                relief="flat", cursor="hand2",
                command=cmd, padx=10, pady=4
            ).pack(side="right", padx=4)

        # Speed slider
        spd_frame = tk.Frame(right, bg=BG_PANEL)
        spd_frame.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 4))

        tk.Label(spd_frame, text="Speed:",
                 bg=BG_PANEL, fg=FG_GREY,
                 font=FONT_LABEL).pack(side="left", padx=(0, 8))

        self._speed_var = tk.IntVar(value=600)
        speed_slider = tk.Scale(
            spd_frame,
            from_=100, to=2000,
            orient="horizontal",
            variable=self._speed_var,
            bg=BG_PANEL, fg=FG_GREY,
            troughcolor=BG_CARD,
            highlightthickness=0,
            showvalue=False,
            length=160,
        )
        speed_slider.pack(side="left")

        self._lbl_speed = tk.Label(
            spd_frame, text="600 ms / pkt",
            bg=BG_PANEL, fg=FG_GREY, font=FONT_LABEL
        )
        self._lbl_speed.pack(side="left", padx=8)

        def _update_speed_label(*_):
            self._lbl_speed.config(text=f"{self._speed_var.get()} ms / pkt")

        self._speed_var.trace_add("write", _update_speed_label)

        # ── Log panel ────────────────────────────────────────
        log_hdr = tk.Frame(right, bg=BG_PANEL)
        log_hdr.grid(row=3, column=0, sticky="ew", padx=12, pady=(4, 2))
        tk.Label(log_hdr, text="▸ PACKET LOG",
                 bg=BG_PANEL, fg=CLR_TEAL,
                 font=FONT_TITLE).pack(side="left")

        log_frame = tk.Frame(right, bg=BG_PANEL)
        log_frame.grid(row=4, column=0, sticky="nsew", padx=12, pady=(0, 8))
        log_frame.rowconfigure(0, weight=1)
        log_frame.columnconfigure(0, weight=1)
        right.rowconfigure(4, weight=1)

        self._log = tk.Text(
            log_frame,
            bg="#020617", fg=FG_WHITE,
            font=FONT_MONO, relief="flat",
            bd=0, padx=10, pady=8,
            state="disabled",
            cursor="arrow",
            wrap="none",
            highlightthickness=1,
            highlightbackground=FG_DIM,
        )
        log_vsb = ttk.Scrollbar(log_frame, orient="vertical",
                                command=self._log.yview,
                                style="Dark.Vertical.TScrollbar")
        log_hsb = ttk.Scrollbar(log_frame, orient="horizontal",
                                command=self._log.xview,
                                style="Dark.Vertical.TScrollbar")
        self._log.configure(yscrollcommand=log_vsb.set,
                            xscrollcommand=log_hsb.set)

        self._log.grid(row=0, column=0, sticky="nsew")
        log_vsb.grid(row=0, column=1, sticky="ns")
        log_hsb.grid(row=1, column=0, sticky="ew")

        # Color tags
        self._log.tag_configure("allow",   foreground=CLR_GREEN)
        self._log.tag_configure("deny",    foreground=CLR_RED)
        self._log.tag_configure("rule",    foreground=CLR_PURPLE)
        self._log.tag_configure("header",  foreground=CLR_TEAL)
        self._log.tag_configure("dim",     foreground=FG_DIM)
        self._log.tag_configure("amber",   foreground=CLR_AMBER)

        # Header line
        self._log_append(
            "TIME       SRC              DEST             PORT   PROTO   RESULT    RULE#\n",
            "header"
        )
        self._log_append(
            "─" * 85 + "\n",
            "dim"
        )

    # ── Event Handlers ───────────────────────────────────────

    def _on_add_rule(self):
        """Validate inputs and add rule to the firewall engine + UI table."""
        src  = "ANY" if self._src_any.get()  else self._src_entry.get().strip()
        dest = "ANY" if self._dest_any.get() else self._dest_entry.get().strip()
        port = "ANY" if self._port_any.get() else self._get_port_value()
        protocol = self._protocol_cb.get()
        action   = self._action_cb.get()

        # ── Validation ────────────────────────────────────────
        if src  == "" or (not self._src_any.get()  and not self._valid_ip(src)):
            messagebox.showerror("Invalid Input", "Source IP is invalid.\nUse dotted-decimal format or check ANY.")
            return
        if dest == "" or (not self._dest_any.get() and not self._valid_ip(dest)):
            messagebox.showerror("Invalid Input", "Destination IP is invalid.\nUse dotted-decimal format or check ANY.")
            return
        if port is None:
            messagebox.showerror("Invalid Input", "Port must be a number between 1 and 65535.")
            return

        self.firewall.add_rule(src, dest, port, protocol, action)
        self._refresh_rule_table()

        # Log the new rule
        self._log_append(
            f"[RULE ADDED]  #{len(self.firewall.rules)}  "
            f"{src:<16} → {dest:<16}  port={str(port):<6}  "
            f"proto={protocol:<6}  action={action}\n",
            "rule"
        )

    def _on_remove_rule(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showinfo("Remove Rule", "Please select a rule to remove.")
            return
        item  = sel[0]
        index = self._tree.index(item)  # 0-based
        rule  = self.firewall.rules[index]
        self.firewall.remove_rule(index)
        self._refresh_rule_table()
        self._log_append(
            f"[RULE REMOVED]  #{index + 1}  {rule['src']} → {rule['dest']}  "
            f"port={rule['port']}  proto={rule['protocol']}  action={rule['action']}\n",
            "amber"
        )

    def _on_clear_rules(self):
        if not self.firewall.rules:
            return
        if messagebox.askyesno("Clear Rules", "Remove ALL firewall rules?"):
            self.firewall.clear_rules()
            self._refresh_rule_table()
            self._log_append("[ALL RULES CLEARED]\n", "amber")

    def _on_start(self):
        if self.running:
            return
        if not self.firewall.rules:
            messagebox.showwarning(
                "No Rules",
                "No firewall rules are defined.\n"
                "All traffic will be DENIED by default policy.\n"
                "Add rules first for meaningful simulation."
            )
        self.running = True
        self._lbl_status.config(text="● RUNNING", fg=CLR_GREEN)
        self._schedule_next_packet()

    def _on_stop(self):
        self.running = False
        if self._sim_job:
            self.root.after_cancel(self._sim_job)
            self._sim_job = None
        self._lbl_status.config(text="● STOPPED", fg=CLR_RED)

    def _on_clear_log(self):
        self._log.config(state="normal")
        self._log.delete("1.0", "end")
        self._log.config(state="disabled")
        self._log_append(
            "TIME       SRC              DEST             PORT   PROTO   RESULT    RULE#\n",
            "header"
        )
        self._log_append("─" * 85 + "\n", "dim")

    # ── Simulation Core ──────────────────────────────────────

    def _schedule_next_packet(self):
        """Schedule a single packet evaluation after the user-chosen delay."""
        if not self.running:
            return
        delay = self._speed_var.get()
        self._sim_job = self.root.after(delay, self._process_packet)

    def _process_packet(self):
        """Generate, evaluate, log one packet then schedule the next."""
        if not self.running:
            return

        packet = PacketGenerator.generate()
        result, rule_idx = self.firewall.check_packet(packet)

        if result == "ALLOW":
            self.allowed += 1
            tag  = "allow"
        else:
            self.denied += 1
            tag  = "deny"

        rule_str = f"#{rule_idx + 1}" if rule_idx >= 0 else "DEFAULT"
        ts       = time.strftime("%H:%M:%S")
        msg = (
            f"{ts}  {packet['src']:<16} {packet['dest']:<16} "
            f"{str(packet['port']):<6} {packet['protocol']:<7} "
            f"{result:<9} {rule_str}\n"
        )
        self._log_append(msg, tag)
        self._update_stats()
        self._schedule_next_packet()

    # ── Helpers ──────────────────────────────────────────────

    def _refresh_rule_table(self):
        """Rebuild the treeview from the current rule list."""
        for item in self._tree.get_children():
            self._tree.delete(item)

        if not self.firewall.rules:
            self._empty_label.lift()
        else:
            self._empty_label.lower()
            for i, rule in enumerate(self.firewall.rules):
                tags = []
                tags.append("allow" if rule["action"] == "ALLOW" else "deny")
                tags.append("odd" if i % 2 == 0 else "even")
                self._tree.insert(
                    "", "end",
                    values=(
                        i + 1,
                        rule["src"],
                        rule["dest"],
                        rule["port"],
                        rule["protocol"],
                        rule["action"],
                    ),
                    tags=tags,
                )

    def _update_stats(self):
        total = self.allowed + self.denied
        self._lbl_allowed.config(text=f"✔ ALLOWED:  {self.allowed}")
        self._lbl_denied.config( text=f"✘ DENIED:   {self.denied}")
        self._lbl_total.config(  text=f"TOTAL:  {total}")

    def _log_append(self, text: str, tag: str = ""):
        """Thread-safe append to the log Text widget."""
        self._log.config(state="normal")
        if tag:
            self._log.insert("end", text, tag)
        else:
            self._log.insert("end", text)
        self._log.see("end")
        self._log.config(state="disabled")

    def _get_port_value(self):
        """Return port as int, or None if invalid."""
        try:
            val = int(self._port_spin.get())
            if 1 <= val <= 65535:
                return val
            return None
        except ValueError:
            return None

    @staticmethod
    def _valid_ip(ip: str) -> bool:
        """Basic IPv4 validation."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False


# ─────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    root = tk.Tk()
    app  = FirewallApp(root)

    # ── Pre-load a few demo rules so the UI is not empty ─────
    demo_rules = [
        ("ANY",         "ANY",      "ANY", "HTTPS",  "ALLOW"),
        ("ANY",         "ANY",      "ANY", "HTTP",   "ALLOW"),
        ("ANY",         "ANY",      "ANY", "DNS",    "ALLOW"),
        ("ANY",         "ANY",       22,   "TCP",    "DENY"),   # block SSH
        ("ANY",         "ANY",       23,   "TCP",    "DENY"),   # block Telnet
        ("ANY",         "ANY",     3389,   "TCP",    "DENY"),   # block RDP
        ("ANY",         "ANY",      "ANY", "ANY",    "DENY"),   # catch-all deny
    ]
    for src, dest, port, proto, action in demo_rules:
        app.firewall.add_rule(src, dest, port, proto, action)
    app._refresh_rule_table()
    app._log_append("[DEMO RULES LOADED]  — 7 rules pre-configured.\n", "amber")
    app._log_append(
        "Tip: Start simulation to watch live packet evaluation against these rules.\n",
        "dim"
    )

    root.mainloop()
