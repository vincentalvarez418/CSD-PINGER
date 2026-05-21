import tkinter as tk
from tkinter import ttk
import subprocess, platform, re, threading, datetime, json, os, sys, csv

# ── Constants ────────────────────────────────────────────────────
PING_COUNT  = 10
IS_WIN      = platform.system().lower() == "windows"

INTERVAL_CYCLE = [
    ("OFF", 0),
    ("1 min", 60),
    ("5 min", 300),
]

# ── Palette ──────────────────────────────────────────────────────
BG          = "#080b10"
CARD_BG     = "#0d1117"
BORDER      = "#1c2333"
TEXT        = "#cdd9e5"
TEXT_DIM    = "#637080"
GREEN       = "#3fb950"; GREEN_DIM  = "#0b2114"
YELLOW      = "#d29922"; YELLOW_DIM = "#261e07"
ORANGE      = "#e0823d"; ORANGE_DIM = "#2a1508"
RED         = "#f85149"; RED_DIM    = "#2a0d0c"
ACCENT      = "#58a6ff"; ACCENT_DIM = "#0c1d3a"

BLINK_FAST  = 320
BLINK_MILD  = 720

CARD_RED    = "#1a0a09"
CARD_ORANGE = "#1a0e06"
CARD_YELLOW = "#141006"

DIM_TEXT      = "#2a3340"
DIM_TEXT_MID  = "#1e2830"
DIM_BORDER    = "#111822"
DIM_CARD_BG   = "#0a0e14"
DIM_ACCENT    = "#1e3550"
DIM_ACCENT_BG = "#080f18"

# ── Severity helpers ─────────────────────────────────────────────
SEV_STYLE = {
    "green":        (GREEN,  GREEN_DIM,  None),
    "yellow":       (YELLOW, YELLOW_DIM, None),
    "yellow_blink": (YELLOW, YELLOW_DIM, BLINK_MILD),
    "orange_blink": (ORANGE, ORANGE_DIM, BLINK_MILD),
    "red_blink":    (RED,    RED_DIM,    BLINK_FAST),
}

def loss_severity(pct):
    if pct <= 1:   return "green"
    if pct <= 9:   return "yellow_blink"
    if pct <= 49:  return "yellow"
    if pct <= 99:  return "orange_blink"
    return "red_blink"

def should_log(sev):
    return sev in ("orange_blink", "red_blink")

# ── Config / persistence ─────────────────────────────────────────
def _base():
    return os.path.dirname(sys.executable if getattr(sys, "frozen", False) else os.path.abspath(__file__))

CONFIG_PATH = os.path.join(_base(), "nm_config.json")
MISC_PATH   = os.path.join(_base(), "nm_misc.json")
LOG_PATH    = os.path.join(_base(), "nm_log.csv")

DEFAULT_HOSTS = [
    {"vm_name": "VM 01", "ip": "", "physical_name": "", "system_name": ""},
    {"vm_name": "VM 02", "ip": "", "physical_name": "", "system_name": ""},
    {"vm_name": "VM 03", "ip": "", "physical_name": "", "system_name": ""},
    {"vm_name": "VM 04", "ip": "", "physical_name": "", "system_name": ""},
    {"vm_name": "VM 05", "ip": "", "physical_name": "", "system_name": ""},
    {"vm_name": "VM 06", "ip": "", "physical_name": "", "system_name": ""},
]

_DEFAULT_VM_PATTERN = re.compile(r"^VM\s+\d+$", re.IGNORECASE)

def load_hosts():
    try:
        with open(CONFIG_PATH) as f:
            d = json.load(f)
            if isinstance(d, list) and d:
                return d
    except Exception:
        pass
    return [dict(h) for h in DEFAULT_HOSTS]

def save_hosts(hosts):
    try:
        with open(CONFIG_PATH, "w") as f:
            json.dump(hosts, f, indent=2)
    except Exception:
        pass
    
def load_misc():
    try:
        with open(MISC_PATH) as f:
            d = json.load(f)
            if isinstance(d, list):
                return d
    except Exception:
        pass
    return []

def save_misc(entries):
    try:
        with open(MISC_PATH, "w") as f:
            json.dump(entries, f, indent=2)
    except Exception:
        pass

def log_event(what, vm_name, ip, diagnostic):
    is_new = not os.path.exists(LOG_PATH)
    try:
        with open(LOG_PATH, "a", newline="") as f:
            w = csv.writer(f)
            if is_new:
                w.writerow(["timestamp", "what", "server", "ip", "diagnostic"])
            w.writerow([
                datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                what, vm_name, ip, diagnostic
            ])
    except Exception:
        pass

# ── Ping ─────────────────────────────────────────────────────────
def ping_host(ip, count, dot_callback=None):
    if not ip or ip == "0.0.0.0":
        return {"status": "EMPTY", "loss": 0, "avg": "—", "recv": 0}

    flag = "-n" if IS_WIN else "-c"
    kw   = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WIN else {}

    try:
        proc = subprocess.Popen(
            ["ping", flag, str(count), "-w", "700", ip],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, **kw
        )
    except Exception:
        return {"status": "ERROR", "loss": 100, "avg": "—", "recv": 0}

    out_lines = []
    dot_idx   = 0
    try:
        for line in proc.stdout:
            out_lines.append(line)
            lo = line.lower()
            is_reply = ("reply from" in lo or "bytes from" in lo or
                        "icmp_seq" in lo or "seq=" in lo)
            is_miss  = ("timed out" in lo or "timeout" in lo or
                        "unreachable" in lo or "request" in lo or
                        "no route" in lo)
            if is_reply or is_miss:
                if dot_callback and dot_idx < count:
                    dot_callback(dot_idx, is_reply)
                    dot_idx += 1
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        return {"status": "TIMEOUT", "loss": 100, "avg": "—", "recv": 0}

    out = "".join(out_lines)

    loss_m = re.search(r"(\d+)%\s+loss", out)
    loss   = int(loss_m.group(1)) if loss_m else 100

    avg_ms = "—"
    avg_m  = re.search(r"Average\s*=\s*(\d+)ms", out)
    if not avg_m:
        avg_m = re.search(r"[\d.]+/([\d.]+)/[\d.]+", out)
    if avg_m:
        avg_ms = avg_m.group(1) + " ms"

    recv_m = re.search(r"Received\s*=\s*(\d+)", out)
    if not recv_m:
        recv_m = re.search(r"(\d+) received", out)
    recv = int(recv_m.group(1)) if recv_m else (count if loss == 0 else 0)

    out_lo = out.lower()
    if "unreachable" in out_lo or "destination host unreachable" in out_lo:
        status = "UNREACHABLE"
    elif loss == 100 and ("timed out" in out_lo or "timeout" in out_lo or "request" in out_lo):
        status = "TIMEOUT"
    elif loss == 100:
        status = "DOWN"
    else:
        status = "UP"

    return {"status": status, "loss": loss, "avg": avg_ms, "recv": recv}


# ── Misc Sidebar Row ─────────────────────────────────────────────
class MiscRow(tk.Frame):
    def __init__(self, parent, entry, sidebar, **kw):
        super().__init__(parent, bg=CARD_BG, **kw)
        self.entry   = dict(entry)
        self.sidebar = sidebar
        self._blink_job   = None
        self._blink_state = True
        self._build()
        if self.entry.get("ip"):
            self.after(200, self._ping)

    def _build(self):
        self.configure(highlightbackground=BORDER, highlightthickness=1, padx=8, pady=6)

        top = tk.Frame(self, bg=CARD_BG)
        top.pack(fill="x")

        self.dot = tk.Label(top, text="●", font=("Consolas", 10),
                            fg=TEXT_DIM, bg=CARD_BG)
        self.dot.pack(side="left", padx=(0, 6))

        self.name_lbl = tk.Label(top, text=self.entry.get("name", "—"),
                                 font=("Consolas", 9, "bold"), fg=TEXT,
                                 bg=CARD_BG, anchor="w")
        self.name_lbl.pack(side="left", fill="x", expand=True)

        tk.Button(top, text="✕", font=("Consolas", 7),
                  fg=TEXT_DIM, bg=CARD_BG,
                  activeforeground=RED, activebackground=CARD_BG,
                  relief="flat", bd=0, cursor="hand2",
                  command=self._remove).pack(side="right")

        bot = tk.Frame(self, bg=CARD_BG)
        bot.pack(fill="x", pady=(2, 0))

        self.ip_lbl = tk.Label(bot, text=self.entry.get("ip", "—"),
                               font=("Consolas", 8), fg=TEXT_DIM, bg=CARD_BG, anchor="w")
        self.ip_lbl.pack(side="left", fill="x", expand=True)

        self.status_lbl = tk.Label(bot, text="—",
                                   font=("Consolas", 7, "bold"), fg=TEXT_DIM, bg=CARD_BG)
        self.status_lbl.pack(side="right")

    def _remove(self):
        self._stop_blink()
        self.sidebar.remove_row(self)

    def _ping(self):
        ip = self.entry.get("ip", "")
        if not ip or ip == "0.0.0.0":
            return
        self.dot.config(fg=YELLOW)
        self.status_lbl.config(text="...", fg=YELLOW)
        def run():
            res = ping_host(ip, 10)
            self.after(0, self._apply_result, res)
        threading.Thread(target=run, daemon=True).start()

    def _apply_result(self, res):
        status = res["status"]
        loss   = res["loss"]
        if status in ("TIMEOUT", "UNREACHABLE", "DOWN", "ERROR"):
            self.status_lbl.config(text="DOWN", fg=RED)
            self._start_blink(RED, BLINK_FAST)
            log_event(f"{status} | loss={loss}%", self.entry.get("name", ""), 
                      self.entry.get("ip", ""), f"sev=red_blink")
        elif status == "EMPTY":
            self.status_lbl.config(text="—", fg=TEXT_DIM)
            self._stop_blink()
            self.dot.config(fg=TEXT_DIM)
        else:
            sev = loss_severity(loss)
            fg  = SEV_STYLE[sev][0]
            txt = "OK" if loss <= 1 else f"{loss}% loss"
            self.status_lbl.config(text=txt, fg=fg)
            self._stop_blink()
            self.dot.config(fg=fg)

    def _start_blink(self, color, speed):
        self._stop_blink()
        self._blink_state = True
        def tick():
            if self._blink_state:
                self.dot.config(fg=color)
                self.configure(highlightbackground=color, bg=CARD_RED)
                self._tint_children(CARD_RED)
            else:
                self.dot.config(fg=CARD_BG)
                self.configure(highlightbackground=BORDER, bg=CARD_BG)
                self._tint_children(CARD_BG)
            self._blink_state = not self._blink_state
            self._blink_job = self.after(speed, tick)
        tick()

    def _stop_blink(self):
        if self._blink_job:
            self.after_cancel(self._blink_job)
            self._blink_job = None
        self.configure(highlightbackground=BORDER, bg=CARD_BG)
        self._tint_children(CARD_BG)

    def _tint_children(self, color):
        for w in self.winfo_children():
            try: w.configure(bg=color)
            except Exception: pass
            for ww in w.winfo_children():
                try: ww.configure(bg=color)
                except Exception: pass

    def ping_now(self):
        self._ping()


# ── Misc Sidebar ─────────────────────────────────────────────────
class MiscSidebar(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG, **kw)
        self.rows = []
        self._build()
        self._load()

    def _build(self):
        hdr = tk.Frame(self, bg=BG)
        hdr.pack(fill="x", pady=(0, 6))

        tk.Label(hdr, text="MISC", font=("Consolas", 9, "bold"),
                 fg=TEXT_DIM, bg=BG).pack(side="left")

        tk.Button(hdr, text="⟳", font=("Consolas", 9),
                  fg=TEXT_DIM, bg=BG,
                  activeforeground=ACCENT, activebackground=BG,
                  relief="flat", bd=0, cursor="hand2",
                  command=self._ping_all).pack(side="right")

        self.list_frame = tk.Frame(self, bg=BG)
        self.list_frame.pack(fill="both", expand=True)

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", pady=(8, 6))

        # Toggle button row
        self._add_visible = False
        toggle_row = tk.Frame(self, bg=BG)
        toggle_row.pack(fill="x")
        self._toggle_btn = tk.Button(
            toggle_row, text="+ ADD HOST",
            font=("Consolas", 8, "bold"),
            fg=TEXT_DIM, bg=BG,
            activeforeground=ACCENT, activebackground=BG,
            relief="flat", bd=0, cursor="hand2",
            anchor="w",
            command=self._toggle_add_panel)
        self._toggle_btn.pack(side="left", fill="x", expand=True)

        # Collapsible add panel
        self._add_panel = tk.Frame(self, bg=BG)

        self._name_var = tk.StringVar()
        self._ip_var   = tk.StringVar()

        add_f = tk.Frame(self._add_panel, bg=BG)
        add_f.pack(fill="x", pady=(4, 0))

        name_e = tk.Entry(add_f, textvariable=self._name_var,
                          font=("Consolas", 8), fg=TEXT_DIM, bg=CARD_BG,
                          insertbackground=TEXT, relief="flat",
                          highlightbackground=BORDER, highlightthickness=1, width=10)
        name_e.pack(side="left", ipady=3, padx=(0, 3))
        self._setup_ph(name_e, self._name_var, "Name")

        ip_e = tk.Entry(add_f, textvariable=self._ip_var,
                        font=("Consolas", 8), fg=TEXT_DIM, bg=CARD_BG,
                        insertbackground=TEXT, relief="flat",
                        highlightbackground=BORDER, highlightthickness=1, width=12)
        ip_e.pack(side="left", ipady=3, padx=(0, 3))
        self._setup_ph(ip_e, self._ip_var, "IP")

        tk.Button(add_f, text="+", font=("Consolas", 9, "bold"),
                  fg=BG, bg=ACCENT,
                  activeforeground=BG, activebackground="#79b8ff",
                  relief="flat", bd=0, padx=6, pady=3, cursor="hand2",
                  command=self._add_entry).pack(side="left")

        self._msg_lbl = tk.Label(self._add_panel, text="", font=("Consolas", 7),
                                 fg=TEXT_DIM, bg=BG)
        self._msg_lbl.pack(anchor="w", pady=(3, 0))

    def _toggle_add_panel(self):
        if self._add_visible:
            self._add_panel.pack_forget()
            self._toggle_btn.config(text="+ ADD HOST", fg=TEXT_DIM)
            self._add_visible = False
        else:
            self._add_panel.pack(fill="x")
            self._toggle_btn.config(text="▲ ADD HOST", fg=ACCENT)
            self._add_visible = True

    def _setup_ph(self, entry, var, placeholder):
        var.set(placeholder)
        entry.config(fg=TEXT_DIM)
        def fi(_):
            if var.get() == placeholder:
                var.set("")
                entry.config(fg=TEXT)
        def fo(_):
            if not var.get().strip():
                var.set(placeholder)
                entry.config(fg=TEXT_DIM)
        entry.bind("<FocusIn>",  fi)
        entry.bind("<FocusOut>", fo)

    def _load(self):
        for e in load_misc():
            self._create_row(e)

    def _create_row(self, entry):
        row = MiscRow(self.list_frame, entry, self)
        row.pack(fill="x", pady=(0, 4))
        self.rows.append(row)
        return row

    def _add_entry(self):
        name = self._name_var.get().strip()
        ip   = self._ip_var.get().strip()
        if name in ("", "Name"):
            self._msg_lbl.config(text="need a name", fg=YELLOW)
            return
        if not ip or ip == "IP" or not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            self._msg_lbl.config(text="bad IP", fg=RED)
            return
        self._create_row({"name": name, "ip": ip})
        self._save()
        self._name_var.set("Name")
        self._ip_var.set("IP")
        self._msg_lbl.config(text=f"added {name}", fg=GREEN)
        self.after(2000, lambda: self._msg_lbl.config(text=""))

    def remove_row(self, row):
        row.pack_forget()
        row.destroy()
        self.rows.remove(row)
        self._save()

    def _save(self):
        save_misc([r.entry for r in self.rows])

    def _ping_all(self):
        for r in self.rows:
            r.ping_now()


# ── Host Card ────────────────────────────────────────────────────
class HostCard(tk.Frame):
    def __init__(self, parent, host, app, **kw):
        super().__init__(parent, bg=CARD_BG, **kw)
        self.host = dict(host)
        self.app  = app
        self._blink_job   = None
        self._blink_state = True
        self._cur_sev     = "green"
        self.configure(highlightbackground=BORDER, highlightthickness=1, padx=12, pady=18)
        self._build()
        self.after(50, self._apply_dim)

    def _is_unconfigured(self):
        vm  = (self.host.get("vm_name") or "").strip()
        ip  = (self.host.get("ip") or "").strip()
        has_default_name = bool(_DEFAULT_VM_PATTERN.match(vm)) or not vm
        has_no_ip        = not ip or ip == "0.0.0.0"
        return has_default_name and has_no_ip

    def _apply_dim(self):
        dim = self._is_unconfigured()
        bg       = DIM_CARD_BG   if dim else CARD_BG
        border   = DIM_BORDER    if dim else BORDER
        vm_fg    = DIM_TEXT      if dim else TEXT
        ip_fg    = DIM_TEXT_MID  if dim else TEXT_DIM
        stat_fg  = DIM_TEXT_MID  if dim else TEXT_DIM
        dot_fg   = DIM_BORDER    if dim else BORDER
        badge_fg = DIM_ACCENT    if dim else ACCENT
        badge_bg = DIM_ACCENT_BG if dim else ACCENT_DIM

        self.configure(bg=bg, highlightbackground=border)
        self.vm_entry.config(bg=bg, fg=vm_fg)
        if self.badge.cget("text").strip() in ("IDLE", ""):
            self.badge.config(bg=badge_bg, fg=badge_fg)
            self.badge_frame.config(bg=badge_bg)
        self.ip_entry.config(bg=bg, fg=ip_fg)
        self.ip_saved.config(bg=bg)
        self.phys_entry.config(bg=bg)
        self.sys_entry.config(bg=bg)
        for key, w in self.stat_w.items():
            if w.cget("text") in ("—", ""):
                w.config(fg=stat_fg, bg=bg)
        for d in self.dots:
            if d.cget("fg") in (BORDER, DIM_BORDER):
                d.config(fg=dot_fg, bg=bg)
        self.ts_lbl.config(bg=bg)
        self._tint_children(bg)

    def _ph_field(self, parent, key, placeholder, font_spec, fg_active=TEXT, width=18):
        stored = self.host.get(key, "") or ""
        var = tk.StringVar(value=stored if stored else placeholder)
        fg_init = TEXT_DIM if not stored else fg_active
        e = tk.Entry(parent, textvariable=var, font=font_spec,
                     fg=fg_init, bg=CARD_BG, insertbackground=TEXT,
                     relief="flat", bd=0, highlightthickness=0, width=width)
        def focus_in(_=None):
            if var.get() == placeholder:
                var.set("")
                e.config(fg=fg_active)
        def focus_out(_=None):
            v = var.get().strip()
            if not v:
                var.set(placeholder)
                e.config(fg=TEXT_DIM)
                self.host[key] = ""
            else:
                self.host[key] = v
                e.config(fg=fg_active)
            save_hosts([c.host for c in self.app.cards])
            self._apply_dim()
        def key_release(_=None):
            v = var.get()
            if v != placeholder:
                self.host[key] = v
                save_hosts([c.host for c in self.app.cards])
            self._apply_dim()
        e.bind("<FocusIn>", focus_in)
        e.bind("<FocusOut>", focus_out)
        e.bind("<KeyRelease>", key_release)
        return e, var

    def _build(self):
        top = tk.Frame(self, bg=CARD_BG)
        top.pack(fill="x", pady=(0, 0))

        self.vm_entry, self.vm_var = self._ph_field(
            top, "vm_name", "VM Name", ("Consolas", 15, "bold"), fg_active=TEXT, width=14)
        self.vm_entry.pack(side="left")

        self.badge_frame = tk.Frame(top, bg=ACCENT_DIM, padx=7, pady=2)
        self.badge_frame.pack(side="right")
        self.badge = tk.Label(self.badge_frame, text=" IDLE ",
                              font=("Consolas", 8, "bold"), fg=ACCENT, bg=ACCENT_DIM)
        self.badge.pack()

        ip_row = tk.Frame(self, bg=CARD_BG)
        ip_row.pack(fill="x", pady=(0, 0))

        stored_ip = self.host.get("ip", "") or ""
        self.ip_var = tk.StringVar(value=stored_ip if stored_ip else "0.0.0.0")
        self.ip_entry = tk.Entry(ip_row, textvariable=self.ip_var,
                                 font=("Consolas", 9), fg=TEXT_DIM,
                                 bg=CARD_BG, insertbackground=TEXT,
                                 relief="flat", bd=0, highlightthickness=0, width=16)
        self.ip_entry.pack(side="left")
        self.ip_saved = tk.Label(ip_row, text="", font=("Consolas", 7), fg=GREEN, bg=CARD_BG)
        self.ip_saved.pack(side="left", padx=(3, 0))

        self.ip_entry.bind("<FocusIn>",    self._ip_focus_in)
        self.ip_entry.bind("<FocusOut>",   self._ip_save)
        self.ip_entry.bind("<Return>",     self._ip_save)
        self.ip_entry.bind("<KeyRelease>", self._ip_key)

        phys_sys_row = tk.Frame(self, bg=CARD_BG)
        phys_sys_row.pack(fill="x", pady=(0, 0))

        self.phys_entry, _ = self._ph_field(
            phys_sys_row, "physical_name", "Physical Name",
            ("Consolas", 8), fg_active=TEXT_DIM, width=18)
        self.phys_entry.pack(side="left")
        tk.Label(phys_sys_row, text="(", font=("Consolas", 8), fg=TEXT_DIM, bg=CARD_BG).pack(side="left")
        self.sys_entry, _ = self._ph_field(
            phys_sys_row, "system_name", "System Name",
            ("Consolas", 8), fg_active=TEXT_DIM, width=11)
        self.sys_entry.pack(side="left")
        tk.Label(phys_sys_row, text=")", font=("Consolas", 8), fg=TEXT_DIM, bg=CARD_BG).pack(side="left")

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", pady=(3, 3))

        stats = tk.Frame(self, bg=CARD_BG)
        stats.pack(fill="x")
        self.stat_w = {}
        for lbl, key in [("AVERAGE PING", "avg"), ("LOSS", "loss"), ("PACKETS RECV", "recv")]:
            col = tk.Frame(stats, bg=CARD_BG)
            col.pack(side="left", expand=True)
            tk.Label(col, text=lbl, font=("Consolas", 6), fg=TEXT_DIM, bg=CARD_BG).pack()
            v = tk.Label(col, text="—", font=("Consolas", 11, "bold"), fg=TEXT, bg=CARD_BG)
            v.pack()
            self.stat_w[key] = v

        dot_row = tk.Frame(self, bg=CARD_BG)
        dot_row.pack(fill="x", pady=(4, 0))
        self.dots = []
        for _ in range(PING_COUNT):
            d = tk.Label(dot_row, text="●", font=("Consolas", 10), fg=BORDER, bg=CARD_BG)
            d.pack(side="left", padx=1)
            self.dots.append(d)

        bot = tk.Frame(self, bg=CARD_BG)
        bot.pack(fill="x", pady=(3, 0))
        tk.Button(bot, text="PING", font=("Consolas", 8, "bold"),
                  fg=BG, bg=ACCENT, activeforeground=BG, activebackground="#79b8ff",
                  relief="flat", bd=0, padx=8, pady=3, cursor="hand2",
                  command=self._ping_single).pack(side="left")
        self.ts_lbl = tk.Label(bot, text="—", font=("Consolas", 7), fg=TEXT_DIM, bg=CARD_BG)
        self.ts_lbl.pack(side="right")

    def _ip_focus_in(self, _=None):
        if self.ip_var.get() in ("Enter IP…", "0.0.0.0") and not self.host.get("ip"):
            self.ip_var.set("")
            self.ip_entry.config(fg=TEXT)

    def _ip_key(self, _=None):
        self.ip_saved.config(text="")
        if hasattr(self, "_ip_deb"):
            self.after_cancel(self._ip_deb)
        self._ip_deb = self.after(600, self._ip_save)

    def _ip_save(self, _=None):
        val = self.ip_var.get().strip()
        if val and val != "Enter IP…":
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", val):
                old = self.host.get("ip", "")
                self.host["ip"] = val
                self.ip_entry.config(fg=TEXT_DIM)
                self.ip_saved.config(text="✓")
                self.after(2000, lambda: self.ip_saved.config(text=""))
                save_hosts([c.host for c in self.app.cards])
                self._apply_dim()
                if old != val:
                    self._reset_stats()
                    if val != "0.0.0.0":
                        self.after(100, self._ping_single)
            else:
                self.ip_saved.config(text="✗ bad IP")
                self.after(2000, lambda: self.ip_saved.config(text=""))
        elif not val or val == "0.0.0.0":
            self.ip_var.set("0.0.0.0")
            self.ip_entry.config(fg=TEXT_DIM)
            self.host["ip"] = ""
            save_hosts([c.host for c in self.app.cards])
            self._reset_stats()
            self._apply_dim()

    def _stop_blink(self):
        if self._blink_job:
            self.after_cancel(self._blink_job)
            self._blink_job = None
        self.configure(highlightbackground=BORDER, bg=CARD_BG)
        self._tint_children(CARD_BG)

    def _start_blink(self, fg_on, bg_on, fg_off, bg_off, speed, card_tint=None):
        self._stop_blink()
        self._blink_state = True
        def tick():
            if self._blink_state:
                self.badge.config(fg=fg_on,  bg=bg_on)
                self.badge_frame.config(bg=bg_on)
                self.configure(highlightbackground=fg_on, bg=card_tint or CARD_BG)
                self._tint_children(card_tint or CARD_BG)
            else:
                self.badge.config(fg=fg_off, bg=bg_off)
                self.badge_frame.config(bg=bg_off)
                self.configure(highlightbackground=BORDER, bg=CARD_BG)
                self._tint_children(CARD_BG)
            self._blink_state = not self._blink_state
            self._blink_job = self.after(speed, tick)
        tick()

    def _tint_children(self, color):
        for w in self.winfo_children():
            try: w.configure(bg=color)
            except Exception: pass
            for ww in w.winfo_children():
                try: ww.configure(bg=color)
                except Exception: pass
                for www in ww.winfo_children():
                    try: www.configure(bg=color)
                    except Exception: pass

    def _ping_single(self):
        if not self.host.get("ip"):
            return
        self.set_pinging()
        def run():
            def on_dot(idx, success):
                self.after(0, self._update_dot, idx, success)
            result = ping_host(self.host["ip"], PING_COUNT, dot_callback=on_dot)
            self.after(0, self.update_result, result)
        threading.Thread(target=run, daemon=True).start()

    def _update_dot(self, idx, success):
        if idx < len(self.dots):
            self.dots[idx].config(fg=GREEN if success else RED)

    def set_pinging(self):
        self._stop_blink()
        self.badge.config(text=" PINGING ", fg=YELLOW, bg=YELLOW_DIM)
        self.badge_frame.config(bg=YELLOW_DIM)
        for d in self.dots:
            d.config(fg=BORDER)

    def _reset_stats(self):
        self._stop_blink()
        self.configure(highlightbackground=BORDER, bg=CARD_BG)
        self._tint_children(CARD_BG)
        for v in self.stat_w.values():
            v.config(text="—", fg=TEXT)
        for d in self.dots:
            d.config(fg=BORDER)
        self.badge.config(text=" IDLE ", fg=ACCENT, bg=ACCENT_DIM)
        self.badge_frame.config(bg=ACCENT_DIM)
        self.ts_lbl.config(text="—")
        self._apply_dim()

    def update_result(self, stats):
        now    = datetime.datetime.now().strftime("%H:%M:%S")
        status = stats["status"]
        loss   = stats["loss"]
        avg    = stats["avg"]
        recv   = stats["recv"]

        if status in ("TIMEOUT", "UNREACHABLE", "DOWN", "ERROR"):
            sev = "red_blink"
        else:
            sev = loss_severity(loss)

        self._cur_sev = sev
        fg, bg, bspeed = SEV_STYLE[sev]

        badge_map = {
            "UP":          "    OK    ",
            "DOWN":        "   DOWN   ",
            "TIMEOUT":     "NO RESPONSE",
            "UNREACHABLE": "NO RESPONSE",
            "ERROR":       "   ERROR  ",
            "EMPTY":       "   IDLE   ",
        }
        self.badge.config(text=badge_map.get(status, status))

        if bspeed:
            tint = CARD_RED if sev == "red_blink" else CARD_ORANGE if sev == "orange_blink" else CARD_YELLOW
            self._start_blink(fg, bg, TEXT_DIM, BG, bspeed, card_tint=tint)
        else:
            self._stop_blink()
            self.badge.config(fg=fg, bg=bg)
            self.badge_frame.config(bg=bg)
            border_col = fg if sev != "green" else BORDER
            self.configure(highlightbackground=border_col, bg=CARD_BG)
            self._tint_children(CARD_BG)

        self.stat_w["avg"].config(text=avg, fg=fg)
        loss_fg = (GREEN if loss <= 1
                   else RED   if loss == 100
                   else ORANGE if loss >= 50
                   else YELLOW)
        self.stat_w["loss"].config(text=f"{loss}%", fg=loss_fg)
        self.stat_w["recv"].config(text=f"{recv}/{PING_COUNT}", fg=fg)

        for i, d in enumerate(self.dots):
            d.config(fg=fg if i < recv else RED_DIM)

        self.ts_lbl.config(text=f"checked {now}")

        if should_log(sev):
            what = f"{status} | loss={loss}%"
            diag = f"avg={avg}, recv={recv}/{PING_COUNT}, sev={sev}"
            log_event(what, self.host.get("vm_name", ""), self.host.get("ip", ""), diag)


# ── Scrollable Frame ─────────────────────────────────────────────
class ScrollableFrame(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, **kw)
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Dark.Vertical.TScrollbar",
                        gripcount=0, background=ACCENT, darkcolor=BG, lightcolor=BG,
                        troughcolor="#060810", bordercolor=BG,
                        arrowcolor=ACCENT, arrowsize=13)
        style.map("Dark.Vertical.TScrollbar",
                  background=[("active", "#79b8ff"), ("!active", ACCENT)])

        self.canvas = tk.Canvas(self, bg=BG, highlightthickness=0)
        self.sb     = ttk.Scrollbar(self, orient="vertical",
                                    style="Dark.Vertical.TScrollbar",
                                    command=self.canvas.yview)
        self.inner  = tk.Frame(self.canvas, bg=BG)

        self.inner.bind("<Configure>", lambda _: self.canvas.configure(
            scrollregion=self.canvas.bbox("all")))
        self._win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.canvas.bind("<Configure>",
                         lambda e: self.canvas.itemconfig(self._win, width=e.width))
        self.canvas.configure(yscrollcommand=self.sb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.canvas.bind("<MouseWheel>", self._mw)
        self.inner.bind("<MouseWheel>",  self._mw)

    def _mw(self, e):
        self.canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")

    def bind_mw(self, w):
        w.bind("<MouseWheel>", self._mw)
        for c in w.winfo_children():
            self.bind_mw(c)


# ── Main App ─────────────────────────────────────────────────────
class PingApp(tk.Tk):

    def _defocus(self, event):
        widget = event.widget
        if isinstance(widget, (tk.Frame, tk.Canvas, tk.Label)):
            self.focus_set()

    def __init__(self):
        super().__init__()
        self.title("CSD NETWORK MONITOR")
        self.configure(bg=BG)
        self.geometry("1200x760")
        self.resizable(True, True)
        self._auto_job     = None
        self._running      = False
        self._interval_idx = 1
        self.cards         = []
        self._hosts_data   = load_hosts()
        self._build_ui()
        self.after(500, self._ping_all)

    @property
    def _interval(self):
        return INTERVAL_CYCLE[self._interval_idx][1]

    @property
    def _interval_label(self):
        return INTERVAL_CYCLE[self._interval_idx][0]

    def _toggle_add_host(self):
        if self._add_visible:
            self.add_panel.pack_forget()
            self._add_visible = False
        else:
            self.add_panel.pack(fill="x", padx=14, pady=(0, 8))
            self._add_visible = True

    def _build_ui(self):
        # ── Header ──
        hdr = tk.Frame(self, bg=BG, pady=14, padx=18)
        hdr.pack(fill="x")

        left_hdr = tk.Frame(hdr, bg=BG)
        left_hdr.pack(side="left")
        tk.Label(left_hdr, text="◉  CSD NETWORK MONITOR",
                 font=("Consolas", 15, "bold"), fg=TEXT, bg=BG).pack(anchor="w")
        self.status_lbl = tk.Label(left_hdr, text="Initializing…",
                                   font=("Consolas", 8), fg=TEXT_DIM, bg=BG)
        self.status_lbl.pack(anchor="w")

        right_hdr = tk.Frame(hdr, bg=BG)
        right_hdr.pack(side="right")

        # ── Settings panel (collapsible) ──
        self._settings_visible = False
        self._settings_frame   = tk.Frame(self, bg=BG, padx=18, pady=6)

        sf = self._settings_frame
        tk.Label(sf, text="RE-PING INTERVAL", font=("Consolas", 7),
                 fg=TEXT_DIM, bg=BG).pack(side="left", padx=(0, 6))
        iv_btns = tk.Frame(sf, bg=BG)
        iv_btns.pack(side="left", padx=(0, 16))
        self._iv_btns = {}
        for label, secs in INTERVAL_CYCLE:
            b = tk.Button(iv_btns, text=label,
                          font=("Consolas", 8, "bold"),
                          fg=TEXT_DIM, bg=CARD_BG,
                          activeforeground=TEXT, activebackground=BORDER,
                          relief="flat", bd=0, padx=8, pady=4, cursor="hand2",
                          command=lambda l=label: self._user_set_interval(l))
            b.pack(side="left", padx=1)
            self._iv_btns[label] = b

        # Header buttons
        tk.Button(right_hdr, text="⚙",
                  font=("Consolas", 11), fg=TEXT_DIM, bg=BG,
                  activeforeground=TEXT, activebackground=BG,
                  relief="flat", bd=0, padx=6, pady=5, cursor="hand2",
                  command=self._toggle_settings).pack(side="left", padx=(0, 4))

        tk.Button(right_hdr, text="+ HOST",
                  font=("Consolas", 9, "bold"), fg=BG, bg=ACCENT,
                  activeforeground=BG, activebackground="#79b8ff",
                  relief="flat", bd=0, padx=10, pady=5, cursor="hand2",
                  command=self._toggle_add_host).pack(side="left", padx=(0, 8))

        tk.Button(right_hdr, text="  PING ALL  ",
                  font=("Consolas", 9, "bold"), fg=BG, bg=ACCENT,
                  activeforeground=BG, activebackground="#79b8ff",
                  relief="flat", bd=0, padx=10, pady=5, cursor="hand2",
                  command=self._ping_all).pack(side="left")

        tk.Button(right_hdr, text="⛶",
                  font=("Consolas", 13), fg=TEXT_DIM, bg=BG,
                  activeforeground=TEXT, activebackground=BG,
                  relief="flat", bd=0, padx=6, pady=5, cursor="hand2",
                  command=self._toggle_fullscreen).pack(side="left", padx=(6, 0))

        self.log_lbl = tk.Label(right_hdr, text="", font=("Consolas", 7),
                                fg=TEXT_DIM, bg=BG)
        self.log_lbl.pack(side="left", padx=(8, 0))

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x")
        self._settings_anchor = tk.Frame(self, bg=BG, height=0)
        self._settings_anchor.pack(fill="x")

        # ── Add host panel (collapsible, above body) ──
        self._add_visible = False
        self.add_panel = tk.Frame(self, bg=CARD_BG,
                                  highlightbackground=BORDER, highlightthickness=1,
                                  padx=18, pady=10)

        tk.Label(self.add_panel, text="ADD HOST",
                 font=("Consolas", 8, "bold"), fg=TEXT_DIM, bg=CARD_BG
                 ).pack(anchor="w", pady=(0, 5))

        add_row = tk.Frame(self.add_panel, bg=CARD_BG)
        add_row.pack(fill="x")
        fields = [("VM Name", 14), ("IP", 14), ("Physical Name", 16), ("System", 16)]
        self._add_vars = []
        for ph, w in fields:
            e = self._ph_entry(add_row, ph, w)
            e.pack(side="left", ipady=4, padx=(0, 6))
            self._add_vars.append((e, ph))
        tk.Button(add_row, text="+ ADD",
                  font=("Consolas", 9, "bold"), fg=BG, bg=ACCENT,
                  activeforeground=BG, activebackground="#79b8ff",
                  relief="flat", bd=0, padx=10, pady=4, cursor="hand2",
                  command=self._add_host).pack(side="left")

        # ── Body: left card grid + divider + right misc sidebar ──
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True)

        # Left side
        left_body = tk.Frame(body, bg=BG)
        left_body.pack(side="left", fill="both", expand=True)

        self.scroll = ScrollableFrame(left_body, bg=BG)
        self.scroll.pack(fill="both", expand=True)
        self.grid_f = self.scroll.inner
        self.grid_f.configure(padx=14, pady=14)
        for col in range(3):
            self.grid_f.columnconfigure(col, weight=1, uniform="col")

        for i, host in enumerate(self._hosts_data):
            self._add_card(host, i)

        # Vertical divider
        tk.Frame(body, bg=BORDER, width=1).pack(side="left", fill="y")

        # Right side: misc sidebar (fixed width)
        sidebar_outer = tk.Frame(body, bg=BG, width=220)
        sidebar_outer.pack(side="left", fill="y")
        sidebar_outer.pack_propagate(False)

        self.misc = MiscSidebar(sidebar_outer)
        self.misc.pack(fill="both", expand=True, padx=12, pady=12)


        self.bind_all("<Button-1>", lambda e: self.focus_set() if e.widget not in (
            self.grid_f, *[w for card in self.cards for w in card.winfo_children()]
        ) else None)

        self.bind_all("<Button-1>", self._defocus)

        self._refresh_interval_buttons()

    def _ph_entry(self, parent, placeholder, width):
        var = tk.StringVar(value=placeholder)
        e = tk.Entry(parent, textvariable=var, font=("Consolas", 9),
                     fg=TEXT_DIM, bg=BG, insertbackground=TEXT,
                     relief="flat", highlightbackground=BORDER,
                     highlightthickness=1, width=width)
        e.bind("<FocusIn>",  lambda ev, v=var, p=placeholder, w=e:
               (v.set(""), w.config(fg=TEXT)) if v.get() == p else None)
        e.bind("<FocusOut>", lambda ev, v=var, p=placeholder, w=e:
               (v.set(p), w.config(fg=TEXT_DIM)) if not v.get() else None)
        return e

    def _add_card(self, host, idx):
        card = HostCard(self.grid_f, host, self)
        r, c = divmod(idx, 3)
        pad_l = (0, 5) if c == 0 else (5, 5) if c == 1 else (5, 0)
        card.grid(row=r, column=c, sticky="nsew", padx=pad_l, pady=(0, 10))
        self.cards.append(card)
        self.scroll.bind_mw(card)

    def _set_status(self, msg, color=TEXT_DIM):
        self.status_lbl.config(text=msg, fg=color)

    def _refresh_interval_buttons(self):
        cur_label = self._interval_label
        for lbl, btn in self._iv_btns.items():
            btn.config(fg=(BG if lbl == cur_label else TEXT_DIM),
                       bg=(ACCENT if lbl == cur_label else CARD_BG))

    def _user_set_interval(self, label):
        idx = next(i for i, (l, _) in enumerate(INTERVAL_CYCLE) if l == label)
        self._interval_idx = idx
        self._refresh_interval_buttons()
        if self._auto_job:
            self.after_cancel(self._auto_job)
            self._auto_job = None
        if self._interval == 0:
            self._set_status("Auto re-ping OFF", TEXT_DIM)
            return
        self._set_status(f"Auto re-ping every {label}", GREEN)
        self._auto_job = self.after(self._interval * 1000, self._schedule_auto)

    def _ping_all(self):
        if self._running:
            return
        active = [c for c in self.cards if c.host.get("ip")]
        if not active:
            return
        self._running = True
        self._set_status("Pinging all hosts…", YELLOW)
        for c in active:
            c.set_pinging()
        threading.Thread(target=self._ping_thread, args=(active,), daemon=True).start()

    def _ping_thread(self, cards):
        done = [0]
        lock = threading.Lock()
        def one(card):
            def on_dot(idx, success):
                self.after(0, card._update_dot, idx, success)
            res = ping_host(card.host["ip"], PING_COUNT, dot_callback=on_dot)
            self.after(0, card.update_result, res)
            with lock:
                done[0] += 1
                if done[0] == len(cards):
                    self.after(0, self._ping_done)
        for c in cards:
            threading.Thread(target=one, args=(c,), daemon=True).start()

    def _ping_done(self):
        self._running = False
        now = datetime.datetime.now().strftime("%H:%M:%S")
        self._set_status(f"Last run: {now}", TEXT_DIM)
        if os.path.exists(LOG_PATH):
            self.log_lbl.config(text="📋 log", fg=ORANGE)
        self.misc._ping_all() 

    def _toggle_settings(self):
        if self._settings_visible:
            self._settings_frame.pack_forget()
            self._settings_visible = False
        else:
            self._settings_frame.pack(fill="x", after=self._settings_anchor,
                                      padx=18, pady=(0, 4))
            self._settings_visible = True

    def _toggle_fullscreen(self):
        fs = self.attributes("-fullscreen")
        self.attributes("-fullscreen", not fs)
        if not fs:
            self.bind("<Escape>", lambda _: self.attributes("-fullscreen", False))

    def _schedule_auto(self):
        if self._running:
            self._auto_job = self.after(self._interval * 1000, self._schedule_auto)
            return
        self._ping_all()
        if self._interval > 0:
            self._auto_job = self.after(self._interval * 1000, self._schedule_auto)

    def _add_host(self):
        vals     = [e.get().strip() for e, ph in self._add_vars]
        defaults = [ph for _, ph in self._add_vars]
        vm, ip, phys, sys_n = [
            "" if v == defaults[i] else v for i, v in enumerate(vals)
        ]
        if ip and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
            self._set_status("Invalid IP format", RED)
            return
        host = {
            "vm_name":       vm or f"VM {len(self.cards)+1:02d}",
            "ip":            ip,
            "physical_name": phys,
            "system_name":   sys_n,
        }
        self._add_card(host, len(self.cards))
        save_hosts([c.host for c in self.cards])
        self.after(100, lambda: self.scroll.canvas.yview_moveto(1.0))
        for e, ph in self._add_vars:
            e.config(fg=TEXT_DIM)
            e.delete(0, "end")
            e.insert(0, ph)
        self._set_status(f"Added {host['vm_name']} ({ip or 'no IP'})", GREEN)


if __name__ == "__main__":
    app = PingApp()
    app.mainloop()