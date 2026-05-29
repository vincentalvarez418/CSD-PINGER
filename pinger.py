import tkinter as tk
from tkinter import ttk
import subprocess, platform, re, threading, datetime, json, os, sys, csv, socket
from PIL import Image, ImageTk
import ctypes


try:
    from tkinterweb import HtmlFrame
    HAS_WEBVIEW = True
except ImportError:
    HAS_WEBVIEW = False

try:
    import requests
    requests.packages.urllib3.disable_warnings(
        requests.packages.urllib3.exceptions.InsecureRequestWarning
    )
except ImportError:
    requests = None



DELETE_HOLD_MS = 2500
DELETE_BAR_STEPS = 6
DELETE_BAR_INTERVAL = DELETE_HOLD_MS // DELETE_BAR_STEPS

def _asset(relative_path):
    base = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative_path)

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
    {"vm_name": "VM 01", "ip": "", "physical_name": "", "system_name": "", "port": "", "endpoint": ""},
    {"vm_name": "VM 02", "ip": "", "physical_name": "", "system_name": "", "port": "", "endpoint": ""},
    {"vm_name": "VM 03", "ip": "", "physical_name": "", "system_name": "", "port": "", "endpoint": ""},
    {"vm_name": "VM 04", "ip": "", "physical_name": "", "system_name": "", "port": "", "endpoint": ""},
    {"vm_name": "VM 05", "ip": "", "physical_name": "", "system_name": "", "port": "", "endpoint": ""},
    {"vm_name": "VM 06", "ip": "", "physical_name": "", "system_name": "", "port": "", "endpoint": ""},
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
        cleaned = []
        for h in hosts:
            entry = dict(h)
            if entry.get("ip") == "0.0.0.0":
                entry["ip"] = ""
            cleaned.append(entry)
        with open(CONFIG_PATH, "w") as f:
            json.dump(cleaned, f, indent=2)
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

# ── Validation ───────────────────────────────────────────────────
def is_valid_host(value):
    """Check if value is a valid IP address or domain name"""
    if not value:
        return False
    # Strip protocol if present
    value = value.strip()
    if value.lower().startswith("https://"):
        value = value[8:]
    elif value.lower().startswith("http://"):
        value = value[7:]
    # Remove trailing slash
    value = value.rstrip("/")
    # Check if it's a valid IP address
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value):
        return True
    # Check if it's a valid domain name
    if re.match(r"^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", value):
        return True
    return False

def clean_host(value):
    """Clean and return just the host part (IP or domain)"""
    if not value:
        return ""
    value = value.strip()
    if value.lower().startswith("https://"):
        value = value[8:]
    elif value.lower().startswith("http://"):
        value = value[7:]
    value = value.rstrip("/")
    return value

# ── Ping ─────────────────────────────────────────────────────────
def ping_host(ip, count, dot_callback=None):
    if not ip or ip == "0.0.0.0":
        return {"status": "EMPTY", "loss": 0, "avg": "—", "recv": 0}

    flag = "-n" if IS_WIN else "-c"
    kw   = {"creationflags": subprocess.CREATE_NO_WINDOW} if IS_WIN else {}

    try:
        proc = subprocess.Popen(
            ["ping", flag, str(count), "-w", "300", ip],
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


# ── Port Checking ────────────────────────────────────────────────
def check_port(ip, port, timeout=2):
    if not ip or ip == "0.0.0.0":
        return {"status": "EMPTY", "response_time": "—"}
    
    try:
        port_num = int(port)
        if port_num < 1 or port_num > 65535:
            return {"status": "INVALID", "response_time": "—"}
    except (ValueError, TypeError):
        return {"status": "INVALID", "response_time": "—"}
    
    try:
        start = datetime.datetime.now()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port_num))
        elapsed = (datetime.datetime.now() - start).total_seconds() * 1000
        sock.close()
        
        if result == 0:
            return {"status": "OPEN", "response_time": f"{elapsed:.0f}ms"}
        else:
            return {"status": "CLOSED", "response_time": "—"}
    except socket.timeout:
        return {"status": "TIMEOUT", "response_time": "—"}
    except Exception:
        return {"status": "ERROR", "response_time": "—"}


# ── HTTP/S Request ───────────────────────────────────────────────
def check_http(host, port=80, endpoint="", timeout=3):

    if not any(c.isalpha() for c in str(host)):
        return {"status": "EMPTY", "response_time": "—", "status_code": "—", "protocol": "—"}
    
    if not host or host == "0.0.0.0":
        return {"status": "EMPTY", "response_time": "—", "status_code": "—", "protocol": "—"}

    if not requests:
        return {"status": "ERROR", "response_time": "—", "status_code": "no lib", "protocol": "—"}

    try:
        port_num = int(port) if port else 80
    except (ValueError, TypeError):
        port_num = 80

    endpoint_path = endpoint if endpoint else '/'

    # Pick scheme order based on port
    if port_num == 443:
        schemes = ["https"]
    elif port_num == 80:
        schemes = ["http", "https"]
    else:
        schemes = ["https", "http"]

    last_err = "ERROR"
    for scheme in schemes:
        url = f"{scheme}://{host}:{port_num}{endpoint_path}"
        try:
            start = datetime.datetime.now()
            response = requests.get(url, timeout=timeout, verify=False)
            elapsed = (datetime.datetime.now() - start).total_seconds() * 1000
            status_code = response.status_code

            if 200 <= status_code < 300:
                status = "OK"
            elif 300 <= status_code < 400:
                status = "REDIRECT"
            elif 400 <= status_code < 500:
                status = "CLIENT_ERR"
            elif 500 <= status_code < 600:
                status = "SERVER_ERR"
            else:
                status = "UNKNOWN"

            return {
                "status": status,
                "response_time": f"{elapsed:.0f}ms",
                "status_code": status_code,
                "protocol": scheme.upper(),
            }
        except requests.exceptions.Timeout:
            last_err = "TIMEOUT"
        except requests.exceptions.SSLError:
            last_err = "NO_CONNECTION"
        except requests.exceptions.ConnectionError:
            last_err = "NO_CONNECTION"
        except Exception:
            last_err = "ERROR"

    return {"status": last_err, "response_time": "—", "status_code": "—", "protocol": "—"}


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
        self.name_lbl.bind("<Button-3>", lambda e: self._open_edit_modal())

        # Delete button with red hover effect
        delete_btn = tk.Button(top, text="✕", font=("Consolas", 7),
                  fg=TEXT_DIM, bg=CARD_BG,
                  activeforeground=RED, activebackground=CARD_BG,
                  relief="flat", bd=0, cursor="hand2",
                  command=self._remove)
        delete_btn.pack(side="right")
        
        # Red hover effect for delete button
        def delete_enter(e):
            delete_btn.config(fg=RED)
        def delete_leave(e):
            delete_btn.config(fg=TEXT_DIM)
        delete_btn.bind("<Enter>", delete_enter)
        delete_btn.bind("<Leave>", delete_leave)

        bot = tk.Frame(self, bg=CARD_BG)
        bot.pack(fill="x", pady=(2, 0))

        self.ip_lbl = tk.Label(bot, text=self.entry.get("ip", "—"),
                            font=("Consolas", 8), fg=TEXT_DIM, bg=CARD_BG,
                            anchor="w")
        self.ip_lbl.pack(side="left", fill="x", expand=True)
        self.ip_lbl.bind("<Button-3>", lambda e: self._open_edit_modal())

        self.status_lbl = tk.Label(bot, text="—",
                                   font=("Consolas", 7, "bold"), fg=TEXT_DIM, bg=CARD_BG)
        self.status_lbl.pack(side="right")

        dot_row = tk.Frame(self, bg=CARD_BG)
        dot_row.pack(fill="x", pady=(3, 0))
        self.dots = []
        for _ in range(3):
            d = tk.Label(dot_row, text="●", font=("Consolas", 7), fg=BORDER, bg=CARD_BG)
            d.pack(side="left", padx=1)
            self.dots.append(d)

            drag_widgets = (
                self,
                top,
                bot,
                dot_row,
                self.name_lbl,
                self.ip_lbl,
                self.status_lbl,
                self.dot
            )

            for w in drag_widgets:
                w.bind("<ButtonPress-1>", self._drag_start)
                w.bind("<B1-Motion>", self._drag_motion)
                w.bind("<ButtonRelease-1>", self._drag_release)

    def _remove(self):
        self._stop_blink()
        self.sidebar.remove_row(self)

    def _ping(self):
        ip = self.entry.get("ip", "")
        if not ip or ip == "0.0.0.0":
            return
        self.dot.config(fg=YELLOW)
        self.status_lbl.config(text="...", fg=YELLOW)
        for d in self.dots:
            d.config(fg=BORDER)
        def on_dot(idx, success):
            # idx 0-2 → dot 0, idx 3-6 → dot 1, idx 7-9 → dot 2
            slot = 0 if idx <= 2 else 1 if idx <= 6 else 2
            self.after(0, self.dots[slot].config, {"fg": GREEN if success else RED})
        def run():
            res = ping_host(ip, 10, dot_callback=on_dot)
            self.after(0, self._apply_result, res)
        threading.Thread(target=run, daemon=True).start()

    def _apply_result(self, res):
        status = res["status"]
        loss   = res["loss"]
        recv   = res["recv"]
        if status in ("TIMEOUT", "UNREACHABLE", "DOWN", "ERROR"):
            self.status_lbl.config(text="DOWN", fg=RED)
            for d in self.dots: d.config(fg=RED_DIM)
            self._start_blink(RED, BLINK_FAST)
            log_event(f"{status} | loss={loss}%", self.entry.get("name", ""),
                      self.entry.get("ip", ""), "sev=red_blink")
        elif status == "EMPTY":
            self.status_lbl.config(text="—", fg=TEXT_DIM)
            self._stop_blink()
            self.dot.config(fg=TEXT_DIM)
        else:
            sev = loss_severity(loss)
            fg  = SEV_STYLE[sev][0]
            txt = "OK" if loss <= 1 else f"{loss}% loss"
            self.status_lbl.config(text=txt, fg=fg)
            filled = 1 if recv <= 3 else 2 if recv <= 7 else 3
            for i, d in enumerate(self.dots):
                d.config(fg=fg if i < filled else RED_DIM)
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

    def _drag_start(self, event):
        self._drag_start_y = event.y_root

        self.configure(
            highlightbackground=ACCENT,
            highlightthickness=2
        )

        self.lift()

        self.sidebar._drag_row = self

    def _drag_motion(self, event):
        rows = self.sidebar.rows

        if self not in rows:
            return

        idx = rows.index(self)

        dy = event.y_root - self._drag_start_y

        # Reset borders
        for r in rows:
            r.configure(highlightbackground=BORDER)

        # Dragged row
        self.configure(
            highlightbackground=ACCENT,
            highlightthickness=2
        )

        row_height = self.winfo_height() + 4

        # Move UP
        if dy < -(row_height // 2) and idx > 0:

            rows[idx], rows[idx - 1] = rows[idx - 1], rows[idx]

            self._repack(rows)

            self.sidebar._save()

            # Reset anchor AFTER successful swap
            self._drag_start_y = event.y_root

        # Move DOWN
        elif dy > (row_height // 2) and idx < len(rows) - 1:

            rows[idx], rows[idx + 1] = rows[idx + 1], rows[idx]

            self._repack(rows)

            self.sidebar._save()

            # Reset anchor AFTER successful swap
            self._drag_start_y = event.y_root

    def _drag_release(self, event):
        for r in self.sidebar.rows:
            r.configure(
                highlightbackground=BORDER,
                highlightthickness=1,
                bg=CARD_BG
            )

            r._tint_children(CARD_BG)

        self.sidebar._drag_row = None

    def _repack(self, rows):
        for row in rows:
            row.pack_forget()
        for row in rows:
            row.pack(fill="x", pady=(0, 4))

    def ping_now(self):
        self._ping()


    def _edit_press(self, event):
        self._edit_start_x = event.x_root
        self._edit_start_y = event.y_root

    def _edit_release(self, event):
        dx = abs(event.x_root - getattr(self, "_edit_start_x", event.x_root))
        dy = abs(event.y_root - getattr(self, "_edit_start_y", event.y_root))
        if dx < 5 and dy < 5:
            self._open_edit_modal()

    def _open_edit_modal(self):
        modal = tk.Toplevel(self)
        modal.title("")
        modal.configure(bg=BG)
        modal.resizable(False, False)
        modal.transient(self.winfo_toplevel())
        modal.grab_set()

        root = self.winfo_toplevel()
        root.update_idletasks()
        w, h = 400, 240
        x = root.winfo_rootx() + (root.winfo_width() - w) // 2
        y = root.winfo_rooty() + (root.winfo_height() - h) // 2
        modal.geometry(f"{w}x{h}+{x}+{y}")
        modal.configure(highlightbackground=ACCENT, highlightthickness=1)

        try:
            root._dark_titlebar_for(modal)
        except Exception:
            pass

        card = tk.Frame(modal, bg=CARD_BG, padx=16, pady=14)
        card.pack(fill="both", expand=True)

        tk.Label(card, text="EDIT DEVICE", font=("Consolas", 10, "bold"),
                 fg=TEXT, bg=CARD_BG).pack(anchor="w")
        tk.Frame(card, bg=ACCENT, height=2).pack(fill="x", pady=(8, 12))

        tk.Label(card, text="NAME", font=("Consolas", 8, "bold"),
                 fg=TEXT_DIM, bg=CARD_BG).pack(anchor="w")
        name_wrap = tk.Frame(card, bg=CARD_BG)
        name_wrap.pack(fill="x", pady=(4, 10))
        name_var = tk.StringVar(value=self.entry.get("name", ""))
        name_e = tk.Entry(name_wrap, textvariable=name_var,
                          font=("Consolas", 10), fg=TEXT, bg=CARD_BG,
                          insertbackground=TEXT, relief="flat", bd=0,
                          highlightthickness=0)
        name_e.pack(fill="x", ipady=6)
        tk.Frame(name_wrap, bg=BORDER, height=1).pack(fill="x")

        tk.Label(card, text="IP ADDRESS", font=("Consolas", 8, "bold"),
                 fg=TEXT_DIM, bg=CARD_BG).pack(anchor="w")
        ip_wrap = tk.Frame(card, bg=CARD_BG)
        ip_wrap.pack(fill="x", pady=(4, 12))
        ip_var = tk.StringVar(value=self.entry.get("ip", ""))
        ip_e = tk.Entry(ip_wrap, textvariable=ip_var,
                        font=("Consolas", 10), fg=TEXT, bg=CARD_BG,
                        insertbackground=TEXT, relief="flat", bd=0,
                        highlightthickness=0)
        ip_e.pack(fill="x", ipady=6)
        tk.Frame(ip_wrap, bg=BORDER, height=1).pack(fill="x")

        msg = tk.Label(card, text="", font=("Consolas", 7), fg=TEXT_DIM, bg=CARD_BG)
        msg.pack(anchor="w")

        btn_row = tk.Frame(card, bg=CARD_BG)
        btn_row.pack(fill="x", pady=(8, 0))

        def do_save():
            name = name_var.get().strip()
            ip   = ip_var.get().strip()
            if not name:
                msg.config(text="Need a name", fg=YELLOW)
                return
            cleaned = clean_host(ip)
            if ip and not is_valid_host(cleaned):
                msg.config(text="Invalid IP", fg=RED)
                return
            self.entry["name"] = name
            self.entry["ip"]   = cleaned
            self.name_lbl.config(text=name)
            self.ip_lbl.config(text=cleaned or "—")
            self.sidebar._save()
            modal.destroy()
            self.ping_now()

        tk.Button(btn_row, text="SAVE",
                  font=("Consolas", 9, "bold"), fg=BG, bg=ACCENT,
                  activeforeground=BG, activebackground="#79b8ff",
                  relief="flat", bd=0, padx=12, pady=5, cursor="hand2",
                  command=do_save).pack(side="left")

        cancel_btn = tk.Button(btn_row, text="CANCEL",
                  font=("Consolas", 9, "bold"), fg=TEXT_DIM, bg=CARD_BG,
                  activeforeground=TEXT, activebackground=BORDER,
                  relief="flat", bd=0, padx=12, pady=5, cursor="hand2",
                  command=modal.destroy)
        cancel_btn.pack(side="left", padx=(8, 0))
        def cancel_enter(e): cancel_btn.config(fg=RED)
        def cancel_leave(e): cancel_btn.config(fg=TEXT_DIM)
        cancel_btn.bind("<Enter>", cancel_enter)
        cancel_btn.bind("<Leave>", cancel_leave)

        name_e.focus_set()
        name_e.icursor("end")
        modal.bind("<Escape>", lambda _: modal.destroy())
        modal.bind("<Return>", lambda _: do_save())

    def _open_edit_modal(self):
        modal = tk.Toplevel(self)
        modal.title("")
        modal.configure(bg=BG)
        modal.resizable(False, False)
        modal.transient(self.winfo_toplevel())
        modal.grab_set()

        root = self.winfo_toplevel()
        root.update_idletasks()
        w, h = 400, 240
        x = root.winfo_rootx() + (root.winfo_width() - w) // 2
        y = root.winfo_rooty() + (root.winfo_height() - h) // 2
        modal.geometry(f"{w}x{h}+{x}+{y}")
        modal.configure(highlightbackground=ACCENT, highlightthickness=1)

        try:
            root._dark_titlebar_for(modal)
        except Exception:
            pass

        card = tk.Frame(modal, bg=CARD_BG, padx=16, pady=14)
        card.pack(fill="both", expand=True)

        tk.Label(card, text="EDIT DEVICE", font=("Consolas", 10, "bold"),
                fg=TEXT, bg=CARD_BG).pack(anchor="w")
        tk.Frame(card, bg=ACCENT, height=2).pack(fill="x", pady=(8, 12))

        # Name field
        tk.Label(card, text="NAME", font=("Consolas", 8, "bold"),
                fg=TEXT_DIM, bg=CARD_BG).pack(anchor="w")
        name_wrap = tk.Frame(card, bg=CARD_BG)
        name_wrap.pack(fill="x", pady=(4, 10))
        name_var = tk.StringVar(value=self.entry.get("name", ""))
        name_e = tk.Entry(name_wrap, textvariable=name_var,
                        font=("Consolas", 10), fg=TEXT, bg=CARD_BG,
                        insertbackground=TEXT, relief="flat", bd=0,
                        highlightthickness=0)
        name_e.pack(fill="x", ipady=6)
        tk.Frame(name_wrap, bg=BORDER, height=1).pack(fill="x")

        # IP field
        tk.Label(card, text="IP ADDRESS", font=("Consolas", 8, "bold"),
                fg=TEXT_DIM, bg=CARD_BG).pack(anchor="w")
        ip_wrap = tk.Frame(card, bg=CARD_BG)
        ip_wrap.pack(fill="x", pady=(4, 12))
        ip_var = tk.StringVar(value=self.entry.get("ip", ""))
        ip_e = tk.Entry(ip_wrap, textvariable=ip_var,
                        font=("Consolas", 10), fg=TEXT, bg=CARD_BG,
                        insertbackground=TEXT, relief="flat", bd=0,
                        highlightthickness=0)
        ip_e.pack(fill="x", ipady=6)
        tk.Frame(ip_wrap, bg=BORDER, height=1).pack(fill="x")

        msg = tk.Label(card, text="", font=("Consolas", 7), fg=TEXT_DIM, bg=CARD_BG)
        msg.pack(anchor="w")

        btn_row = tk.Frame(card, bg=CARD_BG)
        btn_row.pack(fill="x", pady=(8, 0))

        def do_save():
            name = name_var.get().strip()
            ip   = ip_var.get().strip()
            if not name:
                msg.config(text="Need a name", fg=YELLOW)
                return
            cleaned = clean_host(ip)
            if ip and not is_valid_host(cleaned):
                msg.config(text="Invalid IP", fg=RED)
                return
            self.entry["name"] = name
            self.entry["ip"]   = cleaned
            self.name_lbl.config(text=name)
            self.ip_lbl.config(text=cleaned or "—")
            self.sidebar._save()
            modal.destroy()
            self.ping_now()

        tk.Button(btn_row, text="SAVE",
                font=("Consolas", 9, "bold"), fg=BG, bg=ACCENT,
                activeforeground=BG, activebackground="#79b8ff",
                relief="flat", bd=0, padx=12, pady=5, cursor="hand2",
                command=do_save).pack(side="left")

        cancel_btn = tk.Button(btn_row, text="CANCEL",
                font=("Consolas", 9, "bold"), fg=TEXT_DIM, bg=CARD_BG,
                activeforeground=TEXT, activebackground=BORDER,
                relief="flat", bd=0, padx=12, pady=5, cursor="hand2",
                command=modal.destroy)
        cancel_btn.pack(side="left", padx=(8, 0))
        def cancel_enter(e): cancel_btn.config(fg=RED)
        def cancel_leave(e): cancel_btn.config(fg=TEXT_DIM)
        cancel_btn.bind("<Enter>", cancel_enter)
        cancel_btn.bind("<Leave>", cancel_leave)

        name_e.focus_set()
        name_e.icursor("end")
        modal.bind("<Escape>", lambda _: modal.destroy())
        modal.bind("<Return>", lambda _: do_save())


# ── Misc Sidebar ─────────────────────────────────────────────────
class MiscSidebar(tk.Frame):
    def __init__(self, parent, **kw):
        super().__init__(parent, bg=BG, **kw)
        self.rows = []
        self._drag_row = None
        self._auto_scroll_job = None
        self._build()
        self._load()
        self._scroll_direction = 1
        self.after(4000, self._auto_scroll_tick)
        
    def _build(self):
        hdr = tk.Frame(self, bg=BG)
        hdr.pack(fill="x", pady=(0, 6))

        tk.Label(hdr, text="BIOMETRIC DEVICES", font=("Consolas", 9, "bold"),
                 fg=TEXT_DIM, bg=BG).pack(side="left")

        tk.Button(hdr, text="⟳", font=("Consolas", 9),
                  fg=TEXT_DIM, bg=BG,
                  activeforeground=ACCENT, activebackground=BG,
                  relief="flat", bd=0, cursor="hand2",
                  command=self._ping_all).pack(side="right")

        scroll_wrap = tk.Frame(self, bg=BG)
        scroll_wrap.pack(fill="both", expand=True)

        # Canvas without the scrollbar attachment
        self.canvas = tk.Canvas(
            scroll_wrap,
            bg=BG,
            highlightthickness=0,
            yscrollincrement=1
        )
        self.canvas.pack(side="left", fill="both", expand=True)

        # Inner frame
        self.list_frame = tk.Frame(self.canvas, bg=BG)

        self.canvas_window = self.canvas.create_window(
            (0, 0),
            window=self.list_frame,
            anchor="nw"
        )

        # Update scrollregion automatically when items are added/removed
        self.list_frame.bind(
            "<Configure>",
            lambda e: self.canvas.configure(
                scrollregion=self.canvas.bbox("all")
            )
        )

        self.canvas.bind(
            "<Configure>",
            lambda e: self.canvas.itemconfig(
                self.canvas_window,
                width=e.width
            )
        )

        # Robust Mousewheel logic that works even when hovering over child widgets
        def _on_mousewheel(event):
            if not self.canvas.winfo_exists():
                return
            # Get current mouse coordinates
            x, y = self.canvas.winfo_pointerxy()
            # Find the exact widget under the cursor
            widget = self.canvas.winfo_containing(x, y)
            
            # If the widget under the mouse is part of this canvas (or the canvas itself)
            if widget and str(widget).startswith(str(self.canvas)):
                # Handle Windows/Mac (event.delta) and Linux (event.num)
                if getattr(event, 'num', 0) == 4 or getattr(event, 'delta', 0) > 0:
                    self.canvas.yview_scroll(-30, "units")
                elif getattr(event, 'num', 0) == 5 or getattr(event, 'delta', 0) < 0:
                    self.canvas.yview_scroll(30, "units")

        # Bind to the top-level window so it intercepts scrolls globally
        top = self.winfo_toplevel()
        top.bind("<MouseWheel>", _on_mousewheel, add="+")
        top.bind("<Button-4>", _on_mousewheel, add="+") # Linux Support
        top.bind("<Button-5>", _on_mousewheel, add="+") # Linux Support

        tk.Frame(self, bg=BORDER, height=1).pack(fill="x", pady=(8, 6))

    # ── Continuous auto-scroll ───────────────────────────────────
    def _is_mouse_over(self):
        """Check if the mouse is currently hovering over the sidebar."""
        try:
            x, y = self.winfo_pointerxy()
            w = self.winfo_containing(x, y)
            return w is not None and str(w).startswith(str(self))
        except Exception:
            return False

    def _auto_scroll_tick(self):
        if not self.canvas.winfo_exists():
            return

        if self._is_mouse_over():
            self._auto_scroll_job = self.after(200, self._auto_scroll_tick)
            return

        top, bottom = self.canvas.yview()

        # All content fits — nothing to scroll
        if top == 0.0 and bottom >= 1.0:
            self._auto_scroll_job = self.after(500, self._auto_scroll_tick)
            return

        # Reverse direction at boundaries
        if bottom >= 1.0:
            self._scroll_direction = -1
        elif top <= 0.0:
            self._scroll_direction = 1

        # Move by a tiny fraction instead of whole units
        step = 0.0009 * self._scroll_direction
        new_top = max(0.0, min(1.0, top + step))
        self.canvas.yview_moveto(new_top)

        self._auto_scroll_job = self.after(50, self._auto_scroll_tick)

    def _ping_all(self):
        for row in self.rows:
            row.ping_now()
            
    def _load(self):
        pass

       
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
        self.after(50, lambda: self.canvas.yview_moveto(1.0))
        return row
    
    def _rebuild_duplicates(self):
        # Remove old duplicates
        for w in self._duplicates:
            w.destroy()
        self._duplicates = []

        # Clone each real row as a visual-only duplicate
        for entry in [r.entry for r in self.rows]:
            dup = MiscRow(self.list_frame, entry, self)
            dup.pack(fill="x", pady=(0, 4))
            self._duplicates.append(dup)

    def _add_entry(self):
        name = self._name_var.get().strip()
        ip   = self._ip_var.get().strip()
        if name in ("", "Name"):
            self._msg_lbl.config(text="need a name", fg=YELLOW)
            return
        if not ip or ip == "IP":
            self._msg_lbl.config(text="bad IP", fg=RED)
            return
        cleaned = clean_host(ip)
        if not is_valid_host(cleaned):
            self._msg_lbl.config(text="bad IP", fg=RED)
            return
        self._create_row({"name": name, "ip": cleaned})
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

    def _open_add_misc_modal(self):
        modal = tk.Toplevel(self)
        modal.title("")
        modal.configure(bg=BG)
        modal.resizable(False, False)
        modal.transient(self.winfo_toplevel())
        modal.grab_set()
        self.after(100, lambda: self.winfo_toplevel()._dark_titlebar_for(modal))

        # Center modal
        root = self.winfo_toplevel()
        root.update_idletasks()

        w, h = 560, 320
        x = root.winfo_rootx() + (root.winfo_width() - w) // 2
        y = root.winfo_rooty() + (root.winfo_height() - h) // 2

        modal.geometry(f"{w}x{h}+{x}+{y}")

        # Border
        modal.configure(highlightbackground=ACCENT, highlightthickness=1)

        card = tk.Frame(
            modal,
            bg=CARD_BG,
            padx=16,
            pady=14
        )
        card.pack(fill="both", expand=True)

        # Title
        tk.Label(
            card,
            text="ADD BIOMETRIC IP",
            font=("Consolas", 10, "bold"),
            fg=TEXT,
            bg=CARD_BG
        ).pack(anchor="w")

        tk.Frame(card, bg=ACCENT, height=2).pack(fill="x", pady=(10, 14))

        # Name
        tk.Label(
            card,
            text="NAME",
            font=("Consolas", 8, "bold"),
            fg=TEXT_DIM,
            bg=CARD_BG
        ).pack(anchor="w")

        name_var = tk.StringVar()

        name_wrap = tk.Frame(card, bg=CARD_BG)
        name_wrap.pack(fill="x", pady=(4, 12))

        name_e = tk.Entry(
            name_wrap,
            textvariable=name_var,
            font=("Consolas", 10),
            fg=TEXT,
            bg=CARD_BG,
            insertbackground=TEXT,
            relief="flat",
            bd=0,
            highlightthickness=0
        )
        name_e.pack(fill="x", ipady=7)

        tk.Frame(name_wrap, bg=BORDER, height=1).pack(fill="x", pady=(2, 0))

        # IP
        tk.Label(
            card,
            text="IP ADDRESS",
            font=("Consolas", 8, "bold"),
            fg=TEXT_DIM,
            bg=CARD_BG
        ).pack(anchor="w")

        ip_var = tk.StringVar()

        ip_wrap = tk.Frame(card, bg=CARD_BG)
        ip_wrap.pack(fill="x", pady=(4, 14))

        ip_e = tk.Entry(
            ip_wrap,
            textvariable=ip_var,
            font=("Consolas", 10),
            fg=TEXT,
            bg=CARD_BG,
            insertbackground=TEXT,
            relief="flat",
            bd=0,
            highlightthickness=0
        )
        ip_e.pack(fill="x", ipady=7)

        tk.Frame(ip_wrap, bg=BORDER, height=1).pack(fill="x", pady=(2, 0))

        msg = tk.Label(
            card,
            text="",
            font=("Consolas", 7),
            fg=TEXT_DIM,
            bg=CARD_BG
        )
        msg.pack(anchor="w")

        btn_row = tk.Frame(card, bg=CARD_BG)
        btn_row.pack(fill="x", pady=(12, 0))

        def do_add():
            name = name_var.get().strip()
            ip   = ip_var.get().strip()

            if not name:
                msg.config(text="Need a name", fg=YELLOW)
                return

            cleaned_ip = clean_host(ip)
            if not is_valid_host(cleaned_ip):
                msg.config(text="Invalid IP", fg=RED)
                return

            self._create_row({
                "name": name,
                "ip": cleaned_ip
            })

            self._save()

            modal.destroy()

        tk.Button(
            btn_row,
            text="+ ADD",
            font=("Consolas", 9, "bold"),
            fg=BG,
            bg=ACCENT,
            activeforeground=BG,
            activebackground="#79b8ff",
            relief="flat",
            bd=0,
            padx=12,
            pady=5,
            cursor="hand2",
            command=do_add
        ).pack(side="left")

        # CANCEL button with red hover effect
        cancel_btn = tk.Button(
            btn_row,
            text="CANCEL",
            font=("Consolas", 9, "bold"),
            fg=TEXT_DIM,
            bg=CARD_BG,
            activeforeground=TEXT,
            activebackground=BORDER,
            relief="flat",
            bd=0,
            padx=12,
            pady=5,
            cursor="hand2",
            command=modal.destroy
        )
        cancel_btn.pack(side="left", padx=(8, 0))
        
        # Red hover effect for cancel button
        def cancel_enter(e):
            cancel_btn.config(fg=RED)
        def cancel_leave(e):
            cancel_btn.config(fg=TEXT_DIM)
        cancel_btn.bind("<Enter>", cancel_enter)
        cancel_btn.bind("<Leave>", cancel_leave)

        name_e.focus_set()

        modal.bind("<Escape>", lambda _: modal.destroy())

# ── Host Card ────────────────────────────────────────────────────
class HostCard(tk.Frame):

    def _bind_right_hold(self, widget):
        if isinstance(widget, (tk.Frame, tk.Label, tk.Canvas)):
            widget.bind("<ButtonPress-3>", self._rc_press)
            widget.bind("<ButtonRelease-3>", self._rc_release)
        for child in widget.winfo_children():
            self._bind_right_hold(child)

    def _cancel_hold(self):
        if getattr(self, "_rc_job", None):
            self.after_cancel(self._rc_job)
            self._rc_job = None
        self._rc_step = 0

    def _rc_press(self, _=None):
        if not self.host.get("ip") and not self.host.get("vm_name"):
            return
        self._cancel_hold()
        self._rc_step = 0
        self._rc_active = True
        self._last_ts = getattr(self, "_last_ts", "—")
        self.badge.config(text=" DELETING ", fg=RED, bg=RED_DIM)
        self.badge_frame.config(bg=RED_DIM)
        self.ts_lbl.config(text="▓" * 0 + "░" * DELETE_BAR_STEPS, fg=RED)
        self._rc_tick()

    def _rc_tick(self):
        if not getattr(self, "_rc_active", False):
            return
        self._rc_step += 1
        bar = "▓" * self._rc_step + "░" * (DELETE_BAR_STEPS - self._rc_step)
        self.ts_lbl.config(text=bar, fg=RED)

        if self._rc_step >= DELETE_BAR_STEPS:
            self._rc_job = None
            self._rc_fire()
        else:
            self._rc_job = self.after(DELETE_BAR_INTERVAL, self._rc_tick)

    def _rc_release(self, _=None):
        if getattr(self, "_rc_job", None):
            self.after_cancel(self._rc_job)
            self._rc_job = None
        self._rc_active = False
        self.ts_lbl.config(text=getattr(self, "_last_ts", "—"), fg=TEXT_DIM)
        self.badge.config(text=" IDLE ", fg=ACCENT, bg=ACCENT_DIM)
        self.badge_frame.config(bg=ACCENT_DIM)

    def _rc_fire(self):
        self._rc_active = False
        self.ts_lbl.config(text="DELETING", fg=RED)
        self.after(50, lambda: self.app._remove_card(self))

    def __init__(self, parent, host, app, **kw):
        super().__init__(parent, bg=CARD_BG, **kw)
        self.host = dict(host)
        self.app  = app
        self._blink_job   = None
        self._blink_state = True
        self._cur_sev     = "green"
        self.configure(highlightbackground=BORDER, highlightthickness=1, padx=12, pady=22)
        self.grid_propagate(False)
        self._build()
        self.after(50, self._apply_dim)
        self._rc_job = None
        self._rc_step = 0
        self._rc_active = False
        self._webview_job = None
        self._webview_showing = False
        self._webview_widget = None
        self._drag_start_x = 0
        self._drag_start_y = 0
        self._drag_ghost = None

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
        current_badge = self.badge.cget("text").strip()
        if current_badge == "UNNAMED":
            self.badge.config(fg=TEXT_DIM, bg=BORDER)
            self.badge_frame.config(bg=BORDER)
        elif current_badge == "UNCONFIGURED":
            self.badge.config(fg="#c084fc", bg="#2e1065")
            self.badge_frame.config(bg="#2e1065")
        elif current_badge in ("IDLE", ""):
            self.badge.config(fg=ACCENT, bg=ACCENT_DIM)
            self.badge_frame.config(bg=ACCENT_DIM)
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
    
    def _capture_natural_height(self):
        self.update_idletasks()
        h = self.winfo_height()
        if h > 10:
            self._locked_height = h

    def _schedule_webview(self, url):
        if not HAS_WEBVIEW:
            return
        if self._webview_job:
            self.after_cancel(self._webview_job)
        self._webview_job = self.after(10000, lambda: self._show_webview(url))


    def _animate_dot(self):
        # Self-healing check: only animate if the webview is active and the dot exists
        if not self._webview_showing or not hasattr(self, "_status_dot") or not self._status_dot.winfo_exists():
            return

        self._blink_state = not self._blink_state
        current_fg = GREEN if self._blink_state else "#0a0f1a"
        
        try:
            self._status_dot.configure(fg=current_fg)
        except Exception:
            return 

        self.after(500, self._animate_dot)

    def _show_webview(self, url):
        if not self._locked_height or self._locked_height < 10:
            return

        current_width = self.winfo_width()
        if current_width < 10: current_width = 520 

        self.configure(height=self._locked_height)
        self.grid_propagate(False)
        self.pack_propagate(False)

        self._webview_showing = True
        self._content.pack_forget()

        # 1. Cleanup old elements
        if hasattr(self, "_web_header") and self._web_header.winfo_exists():
            self._web_header.destroy()
        if hasattr(self, "_loading_overlay"):
            self._loading_overlay.destroy()
        if hasattr(self, "_content_container") and self._content_container.winfo_exists():
            self._content_container.destroy()

        self._web_frame.configure(height=self._locked_height, width=current_width)
        self.configure(padx=0, pady=0)
        self._web_frame.pack(fill="both", expand=True)
        self._web_frame.pack_propagate(False)

        self._web_header = tk.Frame(self._web_frame, bg="#0a0f1a", height=26)
        self._web_header.pack(side="top", fill="x")

        tk.Frame(self._web_frame, bg=BORDER, height=1).pack(side="top", fill="x")
        self._web_header.pack_propagate(False)

        # Status Dot (Vertically centered by placing in the header frame)
        self._status_dot = tk.Label(self._web_header, text="●", font=("Consolas", 7), fg=GREEN, bg="#0a0f1a")
        self._status_dot.pack(side="left", padx=(8, 4), pady=(2, 0))
        self._blink_state = True
        self._animate_dot()
        
        domain = url.split("//")[-1].split("/")[0]
        tk.Label(self._web_header, text=domain, font=("Consolas", 7, "bold"), fg=TEXT_DIM, bg="#0a0f1a", anchor="w").pack(side="left", fill="x", expand=True, pady=(2, 0))
        tk.Label(self._web_header, text="LIVE", font=("Consolas", 6, "bold"), fg="#10b981", bg="#0a0f1a").pack(side="right", padx=(0, 8), pady=(2, 0))

        # 3. Create a dedicated container for the content
        self._content_container = tk.Frame(self._web_frame, bg="#0a0f1a")
        self._content_container.pack(side="top", fill="both", expand=True)

        # 4. Add Animated Spinner
        self._loading_overlay = tk.Frame(self._content_container, bg="#0a0f1a")
        self._loading_overlay.place(relx=0.5, rely=0.5, anchor="center")
        self._loading_lbl = tk.Label(self._loading_overlay, text="○ Loading...", font=("Consolas", 10), fg=TEXT_DIM, bg="#0a0f1a")
        self._loading_lbl.pack()
        
        def animate_spinner():
            if not hasattr(self, "_loading_lbl") or not self._loading_lbl.winfo_exists(): return
            frames = ["○ Loading...", "◌ Loading...", "● Loading...", "◌ Loading..."]
            self._spin_state = (getattr(self, "_spin_state", 0) + 1) % len(frames)
            self._loading_lbl.config(text=frames[self._spin_state])
            self.after(200, animate_spinner)
        animate_spinner()

        # 5. Background Task (Offset kept at 105px for best fit)
        import threading
        def fetch_preview():
            try:
                from playwright.sync_api import sync_playwright
                from PIL import Image
                import io

                is_slow_local_site = any(k in url.lower() for k in ["gov.ph", "zamboanga", "httpbin"])
                with sync_playwright() as p:
                    browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-gl-drawing-for-tests"])
                    context = browser.new_context(viewport={"width": 1200, "height": 800})
                    page = context.new_page()
                    
                    if not is_slow_local_site:
                        page.route("**/*", lambda route: route.abort() if route.request.resource_type in ["media", "websocket"] or "analytics" in route.request.url else route.continue_())
                    
                    try:
                        page.goto(url, wait_until="commit" if is_slow_local_site else "networkidle", timeout=5000 if is_slow_local_site else 9000)
                    except Exception: pass
                    
                    page.evaluate("""() => {
                        const style = document.createElement('style');
                        style.innerHTML = `body { margin: 0 !important; padding: 0 !important; transform: scale(0.90); transform-origin: top center; position: relative; top: 10px; width: 100% !important; }`;
                        document.head.appendChild(style);
                        window.scrollTo(0, 0);
                    }""")
                    page.wait_for_timeout(1500 if is_slow_local_site else 800)
                    img_data = page.screenshot(type="jpeg", quality=60, full_page=False)
                    context.close(); browser.close()

                img = Image.open(io.BytesIO(img_data))
                target_h = self._locked_height - 22
                ratio = target_h / img.height
                target_w = int(img.width * ratio)

                img = img.resize(
                    (target_w, target_h),
                    Image.Resampling.LANCZOS
                )
                self.after(0, lambda: display_image(img))
            except Exception as e: print(f"PLAYWRIGHT FETCH ERROR: {e}")

        def display_image(pil_img):
            from PIL import ImageTk
            if not self._webview_showing: return
            if hasattr(self, "_loading_overlay"): self._loading_overlay.destroy()
            for child in self._content_container.winfo_children(): child.destroy()
            self._preview_photo = ImageTk.PhotoImage(pil_img)
            
            tk.Label(
                self._content_container,
                image=self._preview_photo,
                bg="#0a0f1a"
            ).pack(expand=True)

        threading.Thread(target=fetch_preview, daemon=True).start()
        if hasattr(self, "_webview_job") and self._webview_job: self.after_cancel(self._webview_job)
        self._webview_job = self.after(30000, self._hide_webview)



    def _hide_webview(self):
        if not self._webview_showing:
            return
        self._webview_showing = False
        self._web_frame.pack_forget()
        if hasattr(self, "_webview_widget") and self._webview_widget:
            try:
                self._webview_widget.destroy()
            except Exception:
                pass
            self._webview_widget = None
        self._content.pack(fill="both", expand=True)
        self.configure(padx=12, pady=22)
        self.grid_propagate(False)
        self.pack_propagate(False)

    def _build(self):
        self._content = tk.Frame(self, bg=CARD_BG)
        self._content.pack(fill="both", expand=True)
        self._view_area = tk.Frame(self._content, bg=CARD_BG, height=157)
        self._view_area.pack(fill="both", expand=True)
        self._view_area.pack_propagate(False)

        # separate sibling frame
        self._web_frame = tk.Frame(
            self,
            bg=CARD_BG,
            width=520,
            height=0
        )
        self._web_frame.pack_propagate(False)
        self._locked_height = None

        top = tk.Frame(self._view_area, bg=CARD_BG)
        top.pack(fill="x", pady=(0, 0))

        self.vm_entry, self.vm_var = self._ph_field(
            top, "vm_name", "VM Name", ("Consolas", 15, "bold"), fg_active=TEXT, width=14)
        self.vm_entry.pack(side="left")

        self.badge_frame = tk.Frame(top, bg=ACCENT_DIM, padx=7, pady=2)
        self.badge_frame.pack(side="right")
        vm = (self.host.get("vm_name") or "").strip()
        ip = (self.host.get("ip") or "").strip()
        has_default_name = bool(_DEFAULT_VM_PATTERN.match(vm)) or not vm
        if has_default_name and not ip:
            badge_text = " UNNAMED "
        elif not ip:
            badge_text = " UNCONFIGURED "
        else:
            badge_text = " IDLE "
        if badge_text.strip() == "UNNAMED":
            badge_fg, badge_bg = TEXT_DIM, BORDER
        elif badge_text.strip() == "UNCONFIGURED":
            badge_fg, badge_bg = "#c084fc", "#2e1065"
        else:
            badge_fg, badge_bg = ACCENT, ACCENT_DIM
        self.badge = tk.Label(self.badge_frame, text=badge_text,
                            font=("Consolas", 8, "bold"), fg=badge_fg, bg=badge_bg)
        self.badge_frame.config(bg=badge_bg)
        self.badge.pack()

        ip_row = tk.Frame(self._view_area, bg=CARD_BG)
        ip_row.pack(fill="x", pady=(0, 0))

        stored_ip = self.host.get("ip", "") or ""
        self.ip_var = tk.StringVar(value=stored_ip if stored_ip else "0.0.0.0")
        self.ip_entry = tk.Entry(ip_row, textvariable=self.ip_var,
                                 font=("Consolas", 9), fg=TEXT_DIM,
                                 bg=CARD_BG, insertbackground=TEXT,
                                 relief="flat", bd=0, highlightthickness=0, width=16)
        self.ip_entry.pack(side="left", fill="x", expand=True)
        ip_row.pack(fill="x")
        self.ip_saved = tk.Label(ip_row, text="", font=("Consolas", 7), fg=GREEN, bg=CARD_BG)
        self.ip_saved.pack(side="left", padx=(3, 0))

        self.ip_entry.bind("<FocusIn>",    self._ip_focus_in)
        self.ip_entry.bind("<FocusOut>",   self._ip_save)
        self.ip_entry.bind("<Return>",     self._ip_save)
        self.ip_entry.bind("<KeyRelease>", self._ip_key)

        phys_sys_row = tk.Frame(self._view_area, bg=CARD_BG)
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

        # ── Port and HTTP fields ──
        port_http_row = tk.Frame(self._view_area, bg=CARD_BG)
        port_http_row.pack(fill="x", pady=(4, 0))

        tk.Label(port_http_row, text="PORT:", font=("Consolas", 7), fg=TEXT_DIM, bg=CARD_BG).pack(side="left", padx=(0, 3))
        self.port_entry, _ = self._ph_field(
            port_http_row, "port", "",
            ("Consolas", 8), fg_active=TEXT_DIM, width=6)
        self.port_entry.pack(side="left", padx=(0, 8))

        tk.Label(port_http_row, text="ENDPOINT:", font=("Consolas", 7), fg=TEXT_DIM, bg=CARD_BG).pack(side="left", padx=(0, 3))
        self.endpoint_entry, _ = self._ph_field(
            port_http_row, "endpoint", "/api",
            ("Consolas", 8), fg_active=TEXT_DIM, width=10)
        self.endpoint_entry.pack(side="left")

        tk.Frame(self._view_area, bg=BORDER, height=1).pack(fill="x", pady=(3, 3))

        stats = tk.Frame(self._view_area, bg=CARD_BG)
        stats.pack(fill="x")
        self.stat_w = {}
        for lbl, key in [("AVERAGE PING", "avg"), ("LOSS", "loss"), ("PACKETS RECV", "recv"), ("PORT", "port_status"), ("HTTP/S", "http_status")]:
            col = tk.Frame(stats, bg=CARD_BG)
            col.pack(side="left", expand=True)
            tk.Label(col, text=lbl, font=("Consolas", 6), fg=TEXT_DIM, bg=CARD_BG).pack()
            # Use smaller font for port and HTTP to prevent text clipping
            f_size = 9 if key in ("port_status", "http_status") else 11
            v = tk.Label(col, text="—", font=("Consolas", f_size, "bold"), fg=TEXT, bg=CARD_BG)
            v.pack()
            self.stat_w[key] = v

        dot_row = tk.Frame(self._view_area, bg=CARD_BG)
        dot_row.pack(fill="x", pady=(4, 0))
        self.dots = []
        for _ in range(PING_COUNT):
            d = tk.Label(dot_row, text="●", font=("Consolas", 10), fg=BORDER, bg=CARD_BG)
            d.pack(side="left", padx=1, pady=(18, 0))
            self.dots.append(d)

        bot = tk.Frame(self._content, bg=CARD_BG)
        bot.pack(fill="x", pady=(3, 0))
        self.ts_lbl = tk.Label(bot, text="—", font=("Consolas", 7), fg=TEXT_DIM, bg=CARD_BG)
        self.ts_lbl.pack(side="right")
        self._lp_job = None
        self._dragging = False
        self._bind_long_press(self)
        self._bind_right_hold(self)
        self._init_card_drag(self)
        # Capture natural height before any webview activity
        self.after(200, self._capture_natural_height)

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
            cleaned = clean_host(val)
            if is_valid_host(cleaned):
                old = self.host.get("ip", "")
                self.host["ip"] = cleaned
                self.ip_entry.config(fg=TEXT_DIM)
                self.ip_saved.config(text="✓")
                self.after(2000, lambda: self.ip_saved.config(text=""))
                save_hosts([c.host for c in self.app.cards])
                self._apply_dim()
                if old != cleaned:
                    self._reset_stats()
                    if cleaned != "0.0.0.0":
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
            if isinstance(w, tk.Button): continue
            try: w.configure(bg=color)
            except Exception: pass
            for ww in w.winfo_children():
                if isinstance(ww, tk.Button): continue
                try: ww.configure(bg=color)
                except Exception: pass
                for www in ww.winfo_children():
                    if isinstance(www, tk.Button): continue
                    try: www.configure(bg=color)
                    except Exception: pass


    def _ping_single(self):
        if not self.host.get("ip"):
            return
        self.set_pinging()
        def run():
            target   = (self.host.get("ip") or "").strip().lower()
            port_val = (self.host.get("port") or "").strip()
            ep       = (self.host.get("endpoint") or "").strip()
            
            is_raw_ip  = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))
            has_alpha  = bool(re.search(r"[a-z]", target))
            is_domain  = has_alpha and not is_raw_ip

            if is_domain:
                active_port = port_val if port_val else "443"
                
                success_count = 0
                total_time = 0
                valid_times_count = 0
                last_http_result = {}

                for idx in range(PING_COUNT):
                    http_result = check_http(target, active_port, ep)
                    last_http_result = http_result
                    
                    is_ok = http_result.get("status") == "SUCCESS" or "200" in str(http_result.get("status_code", ""))
                    if is_ok:
                        success_count += 1
                        r_time_str = http_result.get("response_time", "").replace("ms", "").strip()
                        if r_time_str.isdigit():
                            total_time += int(r_time_str)
                            valid_times_count += 1
                    
                    self.after(0, self._update_dot, idx, is_ok)

                loss_pct = int(((PING_COUNT - success_count) / PING_COUNT) * 100)
                true_avg_ms = f"{int(total_time / valid_times_count)}ms" if valid_times_count > 0 else "—"

                if success_count > 0:
                    self.after(0, self.update_result, {
                        "status": "UP", 
                        "avg": "—", 
                        "loss": loss_pct, 
                        "recv": success_count
                    })
                    # Keeps column clean and matching the label
                    self.after(0, self._update_port_status, {
                        "status": "OPEN", 
                        "response_time": "Open"
                    })
                    # Moves response metrics directly into the HTTP label target layout
                    status_code = last_http_result.get("status_code", "200")
                    protocol = last_http_result.get("protocol", "HTTPS")
                    self.after(0, self._update_http_status, {
                        "status": "OK",
                        "status_code": f"{status_code} ({true_avg_ms})", 
                        "protocol": protocol,
                        "response_time": true_avg_ms
                    })
                else:
                    port_result = check_port(target, active_port)
                    self.after(0, self._update_port_status, port_result)
                    self.after(0, self.update_result, {
                        "status": "DOWN", 
                        "avg": "—", 
                        "loss": 100, 
                        "recv": 0
                    })
            else:
                # Standalone fallback execution flow for traditional raw IP ping targets
                def on_dot(idx, success):
                    self.after(0, self._update_dot, idx, success)
                result = ping_host(target, PING_COUNT, dot_callback=on_dot)
                self.after(0, self.update_result, result)
                
                if port_val:
                    port_result = check_port(target, port_val)
                    self.after(0, self._update_port_status, port_result)
                self.after(0, self._update_http_status, {
                    "status": "EMPTY", "response_time": "—",
                    "status_code": "—", "protocol": "—"
                })

        threading.Thread(target=run, daemon=True).start()

    def _update_dot(self, idx, success):
        if idx < len(self.dots):
            self.dots[idx].config(fg=GREEN if success else RED)

    def _update_port_status(self, result):
        status = result.get("status", "ERROR")
        response_time = result.get("response_time", "—")
        
        if status == "OPEN":
            fg = GREEN
            text = f"{response_time}"
        elif status == "CLOSED":
            fg = RED
            text = "Closed"
        elif status == "TIMEOUT":
            fg = ORANGE
            text = "Timeout"
        else:
            fg = TEXT_DIM
            text = "—"
        
        self.stat_w["port_status"].config(text=text, fg=fg)

    def _update_http_status(self, result):
        status = result.get("status", "ERROR")
        status_code = result.get("status_code", "—")
        response_time = result.get("response_time", "—")
        protocol = result.get("protocol", "—")

        if status == "EMPTY":
            fg = TEXT_DIM
            text = "—"
        elif status == "OK":
            fg = GREEN
            text = f"{protocol} {status_code}"
        elif status == "REDIRECT":
            fg = YELLOW
            text = f"{protocol} {status_code}"
        elif status == "CLIENT_ERR":
            fg = ORANGE
            text = f"{protocol} {status_code}"
        elif status == "SERVER_ERR":
            fg = RED
            text = f"{protocol} {status_code}"
        elif status == "TIMEOUT":
            fg = ORANGE
            text = "Timeout"
        elif status == "NO_CONNECTION":
            fg = RED
            text = "No Conn"
        elif status == "ERROR":
            fg = RED
            text = "Err"
        else:
            fg = TEXT_DIM
            text = "—"

        self.stat_w["http_status"].config(text=text, fg=fg)

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
        vm = (self.host.get("vm_name") or "").strip()
        ip = (self.host.get("ip") or "").strip()
        has_default_name = bool(_DEFAULT_VM_PATTERN.match(vm)) or not vm
        if has_default_name and not ip:
            badge_text = " UNNAMED "
        elif not ip:
            badge_text = " UNCONFIGURED "
        else:
            badge_text = " IDLE "
        if badge_text.strip() == "UNNAMED":
            badge_fg, badge_bg = TEXT_DIM, BORDER
        elif badge_text.strip() == "UNCONFIGURED":
            badge_fg, badge_bg = "#c084fc", "#2e1065"
        else:
            badge_fg, badge_bg = ACCENT, ACCENT_DIM
        self.badge.config(text=badge_text, fg=badge_fg, bg=badge_bg)
        self.badge_frame.config(bg=badge_bg)
        self.ts_lbl.config(text="")
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
        self._last_ts = f"checked {now}"
        self.ts_lbl.config(text="")

        if should_log(sev):
            what = f"{status} | loss={loss}%"
            diag = f"avg={avg}, recv={recv}/{PING_COUNT}, sev={sev}"
            log_event(what, self.host.get("vm_name", ""), self.host.get("ip", ""), diag)

        target = (self.host.get("ip") or "").strip()
        is_domain = bool(re.search(r"[a-zA-Z]", target)) and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target)
        if is_domain and status == "UP" and not self._webview_showing:
            port = (self.host.get("port") or "443").strip()
            scheme = "https" if port == "443" else "http"
            self._schedule_webview(f"{scheme}://{target}")

    def _init_card_drag(self, widget):
        if isinstance(widget, (tk.Frame, tk.Label)):
            widget.bind("<ButtonPress-1>",   self._card_drag_start, add="+")
            widget.bind("<B1-Motion>",       self._card_drag_motion, add="+")
            widget.bind("<ButtonRelease-1>", self._card_drag_release, add="+")
        for child in widget.winfo_children():
            self._init_card_drag(child)

    def _card_drag_start(self, event):
        self._drag_start_x = event.x_root
        self._drag_start_y = event.y_root
        self._dragging = False

        # Create ghost label that follows cursor
        self._drag_ghost = tk.Toplevel(self)
        self._drag_ghost.overrideredirect(True)
        self._drag_ghost.attributes("-alpha", 0.6)
        self._drag_ghost.configure(bg=ACCENT)
        tk.Label(
            self._drag_ghost,
            text=self.host.get("vm_name", "HOST"),
            font=("Consolas", 10, "bold"),
            fg=BG, bg=ACCENT,
            padx=12, pady=6
        ).pack()
        self._drag_ghost.geometry(f"+{event.x_root + 12}+{event.y_root + 12}")
        self._drag_ghost.withdraw()

    def _card_drag_motion(self, event):
        dx = abs(event.x_root - self._drag_start_x)
        dy = abs(event.y_root - self._drag_start_y)
        if not self._dragging and (dx > 8 or dy > 8):
            self._dragging = True
            self.configure(highlightbackground=ACCENT)
            # Show ghost once dragging starts
            if self._drag_ghost:
                self._drag_ghost.deiconify()
            # Cancel long-press if user starts dragging
            if hasattr(self, "_lp_job") and self._lp_job:
                self.after_cancel(self._lp_job)
                self._lp_job = None
                self.ts_lbl.config(
                    text=self._last_ts if hasattr(self, "_last_ts") else "—",
                    fg=TEXT_DIM
                )
                self.badge.config(
                    text=self._last_badge if hasattr(self, "_last_badge") else " IDLE ",
                    fg=self._last_badge_fg if hasattr(self, "_last_badge_fg") else ACCENT,
                    bg=self._last_badge_bg if hasattr(self, "_last_badge_bg") else ACCENT_DIM
                )
                self.badge_frame.config(
                    bg=self._last_badge_bg if hasattr(self, "_last_badge_bg") else ACCENT_DIM
                )

        if not self._dragging:
            return

        # Move ghost with cursor
        if self._drag_ghost:
            self._drag_ghost.geometry(f"+{event.x_root + 12}+{event.y_root + 12}")

        # Find which card we're hovering over
        x, y = event.x_root, event.y_root
        target = None
        for card in self.app.cards:
            if card is self:
                continue
            cx = card.winfo_rootx()
            cy = card.winfo_rooty()
            cw = card.winfo_width()
            ch = card.winfo_height()
            if cx <= x <= cx + cw and cy <= y <= cy + ch:
                target = card
                break

        # Highlight target
        for card in self.app.cards:
            if card is self:
                continue
            if card is target:
                card.configure(highlightbackground=ACCENT)
            else:
                card.configure(highlightbackground=BORDER)

    def _card_drag_release(self, event):
        # Destroy ghost
        if self._drag_ghost:
            self._drag_ghost.destroy()
            self._drag_ghost = None

        if not getattr(self, "_dragging", False):
            return
        self._dragging = False
        self.configure(highlightbackground=BORDER)

        # Find drop target
        x, y = event.x_root, event.y_root
        target = None
        for card in self.app.cards:
            if card is self:
                continue
            cx = card.winfo_rootx()
            cy = card.winfo_rooty()
            cw = card.winfo_width()
            ch = card.winfo_height()
            if cx <= x <= cx + cw and cy <= y <= cy + ch:
                target = card
                break

        # Reset all highlights
        for card in self.app.cards:
            card.configure(highlightbackground=BORDER)

        if target:
            self.app._swap_cards(self, target)

    def _bind_long_press(self, widget):
            # Only bind on non-interactive widgets to avoid blocking text entry
            if isinstance(widget, (tk.Frame, tk.Label, tk.Canvas)):
                widget.bind("<ButtonPress-1>",   self._lp_press)
                widget.bind("<ButtonRelease-1>", self._lp_release)
            for child in widget.winfo_children():
                self._bind_long_press(child)

    def _lp_press(self, _=None):
        if not self.host.get("ip"):
            return
        self._last_badge = self.badge.cget("text")
        self._last_badge_fg = self.badge.cget("fg")
        self._last_badge_bg = self.badge.cget("bg")
        self.badge.config(text=" RESETTING ", fg=ACCENT, bg=ACCENT_DIM)
        self.badge_frame.config(bg=ACCENT_DIM)
        self._lp_step = 0
        self._lp_tick()

    def _lp_tick(self):
        steps = 6
        interval = 2500  // steps   # 100 ms per step
        self._lp_step += 1
        bar = "▓" * self._lp_step + "░" * (steps - self._lp_step)
        self.ts_lbl.config(text=bar, fg=ACCENT)
        if self._lp_step >= steps:
            self._lp_job = None
            self._lp_fire()
        else:
            self._lp_job = self.after(interval, self._lp_tick)

    def _lp_release(self, _=None):
        if hasattr(self, "_lp_job") and self._lp_job:
            self.after_cancel(self._lp_job)
            self._lp_job = None
            self.ts_lbl.config(text=self._last_ts if hasattr(self, "_last_ts") else "—", fg=TEXT_DIM)
            self.badge.config(text=self._last_badge, fg=self._last_badge_fg, bg=self._last_badge_bg)
            self.badge_frame.config(bg=self._last_badge_bg)

    def _lp_fire(self):
        self._lp_job = None
        self.ts_lbl.config(text=self._last_ts if hasattr(self, "_last_ts") else "—", fg=TEXT_DIM)
        self.badge.config(text="  COMPLETE  ", fg=ACCENT, bg=ACCENT_DIM)
        self.badge_frame.config(bg=ACCENT_DIM)
        self.after(2000, self._ping_single)

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

    def _start_pendulum(self):
        self._pendulum_dir = 1
        self._pendulum_pausing = False
        self._pendulum_job = None
        self._pendulum_tick()

    def _stop_pendulum(self):
        if getattr(self, "_pendulum_job", None):
            self.after_cancel(self._pendulum_job)
            self._pendulum_job = None

    def _pendulum_tick(self):
        if not self.canvas.winfo_exists():
            return
        top, bottom = self.canvas.yview()
        if self._pendulum_dir == 1 and bottom >= 1.0:
            if not self._pendulum_pausing:
                self._pendulum_pausing = True
                self._pendulum_job = self.after(1800, self._pendulum_reverse)
                return
        elif self._pendulum_dir == -1 and top <= 0.0:
            if not self._pendulum_pausing:
                self._pendulum_pausing = True
                self._pendulum_job = self.after(1800, self._pendulum_reverse)
                return
        step = 0.0006 * self._pendulum_dir
        self.canvas.yview_moveto(max(0.0, min(1.0, top + step)))
        self._pendulum_job = self.after(30, self._pendulum_tick)

    def _pendulum_reverse(self):
        self._pendulum_pausing = False
        self._pendulum_dir *= -1
        self._pendulum_job = self.after(30, self._pendulum_tick)

    def _mw(self, e):
        self.canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")

    def bind_mw(self, w):
        w.bind("<MouseWheel>", self._mw)
        for c in w.winfo_children():
            self.bind_mw(c)


# ── Main App ─────────────────────────────────────────────────────
class PingApp(tk.Tk):

    def _remove_card(self, card):
        if card not in self.cards:
            return

        card._stop_blink()
        card._cancel_hold()
        card.grid_forget()
        self.cards.remove(card)

        for w in self.grid_f.winfo_children():
            w.grid_forget()

        for i, c in enumerate(self.cards):
            r, col = divmod(i, 3)
            pad_l = (0, 5) if col == 0 else (5, 5) if col == 1 else (5, 0)
            c.grid(row=r, column=col, sticky="nsew", padx=pad_l, pady=(0, 10))

        save_hosts([c.host for c in self.cards])
        self._set_status(f"Deleted {card.host.get('vm_name', '')}", RED)

    def _start_pendulum_idle_watch(self):
        self._pendulum_idle_job = None
        self._reset_pendulum_idle_timer()

    def _on_search(self, *_):
        query = self._search_var.get().strip().lower()
        if query:
            self._search_clear.pack(side="right")
            # Cancel idle while actively searching
            if self._idle_restore_job:
                self.after_cancel(self._idle_restore_job)
                self._idle_restore_job = None
            self._exit_idle()
        else:
            self._search_clear.pack_forget()
            # Resume idle when search is cleared
            self._idle_restore_job = self.after(5000, self._enter_idle)
        self._filter_cards(query)

    def _clear_search(self):
        self._search_var.set("")
        self._search_entry.focus_set()
        # Restore all biometric rows
        for row in self.misc.rows:
            row.pack(fill="x", pady=(0, 4))

    def _filter_cards(self, query):
        # ── Main cards ──
        if not query:
            # Restore original grid positions
            for card in self.cards:
                info = getattr(card, "_original_grid_info", None)
                if info:
                    card.grid(**info)
                else:
                    card.grid()

            # Restore all biometric rows
            for row in self.misc.rows:
                row.pack(fill="x", pady=(0, 4))
        else:
            matched = [c for c in self.cards if self._card_matches(c.host, query)]
            unmatched = [c for c in self.cards if not self._card_matches(c.host, query)]

            # Save original grid info before touching anything
            for card in self.cards:
                if not hasattr(card, "_original_grid_info"):
                    card._original_grid_info = card.grid_info()

            for card in unmatched:
                card.grid_remove()

            for i, card in enumerate(matched):
                r, col = divmod(i, 3)
                pad_l = (0, 5) if col == 0 else (5, 5) if col == 1 else (5, 0)
                card.grid(row=r, column=col, sticky="nsew", padx=pad_l, pady=(0, 10))

            # Biometric sidebar rows
            for row in self.misc.rows:
                haystack = " ".join([
                    row.entry.get("name", ""),
                    row.entry.get("ip", ""),
                ]).lower()
                if query in haystack:
                    row.pack(fill="x", pady=(0, 4))
                else:
                    row.pack_forget()

    def _card_matches(self, host, query):
        haystack = " ".join([
            host.get("vm_name", ""),
            host.get("ip", ""),
            host.get("physical_name", ""),
            host.get("system_name", ""),
        ]).lower()
        return query in haystack

    def _reset_pendulum_idle_timer(self, event=None):
        if getattr(self, "_pendulum_idle_job", None):
            self.after_cancel(self._pendulum_idle_job)
            self._pendulum_idle_job = None
        self.scroll._stop_pendulum()
        self._pendulum_idle_job = self.after(7000, self._try_start_pendulum)

    def _try_start_pendulum(self):
        if len(self.cards) > 9:
            self.scroll._start_pendulum()

    def _swap_cards(self, card_a, card_b):
        cards = self.app.cards if hasattr(self, "app") else self.cards
        idx_a = self.cards.index(card_a)
        idx_b = self.cards.index(card_b)

        # Swap hosts
        card_a.host, card_b.host = card_b.host, card_a.host

        # Refresh display of both cards
        for card in (card_a, card_b):
            card.vm_var.set(card.host.get("vm_name") or "VM Name")
            card.ip_var.set(card.host.get("ip") or "0.0.0.0")
            card._reset_stats()
            card._apply_dim()
            if card.host.get("ip"):
                card.after(100, card._ping_single)

        save_hosts([c.host for c in self.cards])
        self._set_status(f"Swapped {card_a.host.get('vm_name','')} ↔ {card_b.host.get('vm_name','')}", ACCENT)


    def _dark_titlebar_for(self, win):
        try:
            DWMWA_USE_IMMERSIVE_DARK_MODE = 20
            hwnd = ctypes.windll.user32.GetParent(win.winfo_id())
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd,
                DWMWA_USE_IMMERSIVE_DARK_MODE,
                ctypes.byref(ctypes.c_int(1)),
                ctypes.sizeof(ctypes.c_int)
            )
        except Exception:
            pass

    def _dark_titlebar(self):
        try:
            DWMWA_USE_IMMERSIVE_DARK_MODE = 20
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
            if not hwnd:
                hwnd = self.winfo_id()
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd,
                DWMWA_USE_IMMERSIVE_DARK_MODE,
                ctypes.byref(ctypes.c_int(1)),
                ctypes.sizeof(ctypes.c_int)
            )
        except Exception:
            pass

    def _defocus(self, event):
        widget = event.widget
        if isinstance(widget, (tk.Frame, tk.Canvas, tk.Label)):
            self.focus_set()

    def __init__(self):
        super().__init__()
        self.title("CSD NETWORK PANEL v.5")
        self.configure(bg=BG)
        self.geometry("1200x760")
        self.resizable(True, True)
        try:
            img = Image.open(_asset("assets/images/icon.png"))
            self._win_icon = ImageTk.PhotoImage(img)
            self.iconphoto(True, self._win_icon)
        except Exception:
            pass
        self._auto_job     = None
        self._running      = False
        self._interval_idx = 1
        self.cards         = []
        self._hosts_data   = load_hosts()
        self._build_ui()
        self._ui_hidden = False
        self._pinging_all = False

        self._idle_job = None
        self._ui_hidden = False

        self.minsize(1200, 760)


        self._start_pendulum_idle_watch()
        self.bind("<Motion>", self._reset_pendulum_idle_timer, add="+")
        self.bind_all("<KeyPress>", self._reset_pendulum_idle_timer, add="+")
        self.bind_all("<ButtonPress>", self._reset_pendulum_idle_timer, add="+")


        self.after(100, self._dark_titlebar)
        self.after(500, self._ping_all)

        self._idle_restore_job = None
        self.bind("<Motion>", self._reset_idle_timer, add="+")
        self.bind_all("<KeyPress>", self._reset_idle_timer, add="+")
        self.bind_all("<ButtonPress>", self._reset_idle_timer, add="+")
        self.after(5000, self._enter_idle)

    @property
    def _interval(self):
        return INTERVAL_CYCLE[self._interval_idx][1]

    @property
    def _interval_label(self):
        return INTERVAL_CYCLE[self._interval_idx][0]

    def _toggle_add_host(self):
        self._open_add_host_modal()

    def _open_add_host_modal(self):
        modal = tk.Toplevel(self)
        modal.title("")
        modal.configure(bg=BG)
        modal.resizable(False, False)
        modal.transient(self)
        modal.grab_set()

        modal.update_idletasks()
        w, h = 560, 420
        x = self.winfo_rootx() + (self.winfo_width() - w) // 2
        y = self.winfo_rooty() + (self.winfo_height() - h) // 2
        modal.geometry(f"{w}x{h}+{x}+{y}")
        modal.configure(highlightbackground=ACCENT, highlightthickness=1)
        self.after(100, lambda: self._dark_titlebar_for(modal))

        card = tk.Frame(modal, bg=CARD_BG, padx=18, pady=16)
        card.pack(fill="both", expand=True)

        top = tk.Frame(card, bg=CARD_BG)
        top.pack(fill="x")

        tk.Label(
            top,
            text="ADD HOST",
            font=("Consolas", 10, "bold"),
            fg=TEXT,
            bg=CARD_BG
        ).pack(side="left")

        tk.Label(
            top,
            text="",
            font=("Consolas", 8),
            fg=TEXT_DIM,
            bg=CARD_BG
        ).pack(side="right")

        tk.Frame(card, bg=ACCENT, height=2).pack(fill="x", pady=(10, 14))

        form = tk.Frame(card, bg=CARD_BG)
        form.pack(fill="x")

        fields = [
            ("VM Name", 14),
            ("IP", 14),
            ("Physical Name", 16),
            ("System", 16),
            ("Port", 8),
            ("Endpoint", 14),
        ]

        _vars = []

        for r, (label_text, width) in enumerate(fields):
            row = tk.Frame(form, bg=CARD_BG)
            row.pack(fill="x", pady=(0, 10))

            tk.Label(
                row,
                text=label_text,
                font=("Consolas", 8, "bold"),
                fg=TEXT_DIM,
                bg=CARD_BG,
                width=14,
                anchor="w"
            ).pack(side="left")

            box = tk.Frame(
                row,
                bg=BORDER,
                padx=6,
                pady=1
            )

            e = self._ph_entry(box, label_text, width)

            e.configure(
                bg=BG,
                fg=TEXT,
                insertbackground=TEXT,
                relief="flat",
                bd=0,
                highlightthickness=0
            )

            e.pack(fill="both", expand=True)

            box.pack(
                side="left",
                fill="x",
                expand=True,
                padx=(0, 6),
                ipady=5
            )
            _vars.append((e, label_text))

        msg_lbl = tk.Label(card, text="", font=("Consolas", 7), fg=TEXT_DIM, bg=CARD_BG)
        msg_lbl.pack(anchor="w", pady=(4, 0))

        btn_row = tk.Frame(card, bg=CARD_BG)
        btn_row.pack(fill="x", pady=(16, 0))

        def do_add():
            vals = [e.get().strip() for e, ph in _vars]
            defaults = [ph for _, ph in _vars]

            vm, ip, phys, sys_n, port, endpoint = [
                "" if v == defaults[i] else v
                for i, v in enumerate(vals)
            ]

            if not vm:
                vm = f"VM {len(self.cards) + 1:02d}"

            if ip:
                cleaned_ip = clean_host(ip)
                if not is_valid_host(cleaned_ip):
                    msg_lbl.config(text="Invalid IP format", fg=RED)
                    return
                ip = cleaned_ip

            host = {
                "vm_name": vm,
                "ip": ip,
                "physical_name": phys,
                "system_name": sys_n,
                "port": port,
                "endpoint": endpoint,
            }

            self._add_card(host, len(self.cards))
            save_hosts([c.host for c in self.cards])

            self.after(
                100,
                lambda: self.scroll.canvas.yview_moveto(1.0)
            )

            self._set_status(
                f"Added {host['vm_name']} ({ip or 'no IP'})",
                GREEN
            )

            modal.destroy()

        tk.Button(
            btn_row,
            text="+ ADD",
            font=("Consolas", 9, "bold"),
            fg=BG,
            bg=ACCENT,
            activeforeground=BG,
            activebackground="#79b8ff",
            relief="flat",
            bd=0,
            padx=14,
            pady=6,
            cursor="hand2",
            command=do_add
        ).pack(side="left")

        # CANCEL button with red hover effect
        cancel_btn = tk.Button(
            btn_row,
            text="CANCEL",
            font=("Consolas", 9, "bold"),
            fg=TEXT_DIM,
            bg=CARD_BG,
            activeforeground=TEXT,
            activebackground=BORDER,
            relief="flat",
            bd=0,
            padx=14,
            pady=6,
            cursor="hand2",
            command=modal.destroy
        )
        cancel_btn.pack(side="left", padx=(8, 0))
        
        # Red hover effect for cancel button
        def cancel_enter(e):
            cancel_btn.config(fg=RED)
        def cancel_leave(e):
            cancel_btn.config(fg=TEXT_DIM)
        cancel_btn.bind("<Enter>", cancel_enter)
        cancel_btn.bind("<Leave>", cancel_leave)

        modal.bind("<Escape>", lambda _: modal.destroy())


    def _reset_idle_timer(self, event=None):
        if self._idle_restore_job:
            self.after_cancel(self._idle_restore_job)
            self._idle_restore_job = None
        self._exit_idle()
        # Don't restart idle timer if user is actively searching
        if self.focus_get() == self._search_entry:
            return
        self._idle_restore_job = self.after(5000, self._enter_idle)

    def _enter_idle(self):
        self._ui_hidden = True
        self.hdr.pack_forget()
        if self._settings_visible:
            self._settings_frame.pack_forget()

    def _exit_idle(self):
        if not getattr(self, "_ui_hidden", False):
            return
        self._ui_hidden = False
        self.hdr.pack(fill="x", after=self._hdr_anchor)
        if self._settings_visible:
            self._settings_frame.pack(fill="x", after=self._settings_anchor,
                                    padx=18, pady=(0, 4))
            
    def _build_ui(self):
        # ── Header ──
        self._hdr_anchor = tk.Frame(self, bg=BG, height=0)
        self._hdr_anchor.pack(fill="x")
        self.hdr = tk.Frame(self, bg=BG, pady=14, padx=18)
        self.hdr.pack(fill="x")
        hdr = self.hdr

        left_hdr = tk.Frame(hdr, bg=BG)
        left_hdr.pack(side="left")

        try:
            _img = Image.open(_asset("assets/images/icon.png")).resize((32, 32), Image.LANCZOS)
            self._header_icon = ImageTk.PhotoImage(_img)
            tk.Label(left_hdr, image=self._header_icon, bg=BG).pack(side="left", padx=(0, 8))
        except Exception:
            pass

        tk.Label(left_hdr, text="CSD NETWORK OPERATION PANEL",
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


                # Search bar (in right_hdr, before the ⚙ button)
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", self._on_search)

        search_inner = tk.Frame(right_hdr, bg=CARD_BG,
                                highlightbackground=BORDER, highlightthickness=1)
        search_inner.pack(side="left", padx=(0, 8))

        tk.Label(search_inner, text="⌕", font=("Consolas", 11),
                fg=TEXT_DIM, bg=CARD_BG).pack(side="left", padx=(8, 4))

        self._search_entry = tk.Entry(
            search_inner,
            textvariable=self._search_var,
            font=("Consolas", 9),
            fg=TEXT, bg=CARD_BG,
            insertbackground=TEXT,
            relief="flat", bd=0,
            highlightthickness=0,
            width=25
        )
        self._search_entry.pack(side="left", fill="x", expand=True, ipady=6)
        self._search_entry.bind("<FocusOut>", self._reset_idle_timer)

        self._search_clear = tk.Button(
            search_inner, text="✕",
            font=("Consolas", 8),
            fg=TEXT_DIM, bg=CARD_BG,
            activeforeground=RED, activebackground=CARD_BG,
            relief="flat", bd=0, padx=8, cursor="hand2",
            command=self._clear_search
        )
        self._search_clear.pack(side="right")
        self._search_clear.pack_forget()

        # Header buttons
        tk.Button(right_hdr, text="⚙",
                  font=("Consolas", 11), fg=TEXT_DIM, bg=BG,
                  activeforeground=TEXT, activebackground=BG,
                  relief="flat", bd=0, padx=6, pady=5, cursor="hand2",
                  command=self._toggle_settings).pack(side="left", padx=(0, 4))

        # ADD HOST button with hover effect
        add_host_btn = tk.Button(right_hdr, text="ADD HOST",
                  font=("Consolas", 9, "bold"), fg=BG, bg=ACCENT,
                  activeforeground=BG, activebackground="#79b8ff",
                  relief="flat", bd=0, padx=10, pady=5, cursor="hand2",
                  command=self._toggle_add_host)
        add_host_btn.pack(side="left", padx=(0, 8))
        
        # Hover effect for add host button
        def add_host_enter(e):
            add_host_btn.config(bg="#79b8ff")
        def add_host_leave(e):
            add_host_btn.config(bg=ACCENT)
        add_host_btn.bind("<Enter>", add_host_enter)
        add_host_btn.bind("<Leave>", add_host_leave)

        # + BIO button with hover effect
        bio_btn = tk.Button(right_hdr, text="+ BIO",
                  font=("Consolas", 9, "bold"), fg=BG, bg=ACCENT,
                  activeforeground=BG, activebackground="#79b8ff",
                  relief="flat", bd=0, padx=10, pady=5, cursor="hand2",
                  command=lambda: self.misc._open_add_misc_modal())
        bio_btn.pack(side="left", padx=(0, 8))
        
        # Hover effect for bio button
        def bio_enter(e):
            bio_btn.config(bg="#79b8ff")
        def bio_leave(e):
            bio_btn.config(bg=ACCENT)
        bio_btn.bind("<Enter>", bio_enter)
        bio_btn.bind("<Leave>", bio_leave)
        

        # PING ALL button with hover effect
        self.ping_all_btn = tk.Button(
            right_hdr,
            text="  PING ALL  ",
            font=("Consolas", 9, "bold"),
            fg=BG,
            bg=ACCENT,
            activeforeground=BG,
            activebackground="#79b8ff",
            relief="flat",
            bd=0,
            padx=10,
            pady=5,
            cursor="hand2",
            command=self._ping_all,
        )

        self.ping_all_btn.pack(side="left")

        def ping_all_enter(e):
            if self._ui_hidden:
                return
            self.ping_all_btn.config(bg="#79b8ff")

        def ping_all_leave(e):
            if self._ui_hidden:
                return
            self.ping_all_btn.config(bg=ACCENT)

        self.ping_all_btn.bind("<Enter>", ping_all_enter)
        self.ping_all_btn.bind("<Leave>", ping_all_leave)

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

        tk.Label(self.add_panel, text="+ HOST",
                 font=("Consolas", 8, "bold"), fg=TEXT_DIM, bg=CARD_BG
                 ).pack(anchor="w", pady=(0, 5))

        add_row = tk.Frame(self.add_panel, bg=CARD_BG)
        add_row.pack(fill="x")
        fields = [("VM Name", 14), ("IP", 14), ("Physical Name", 16), ("System Name", 16), ("Port", 8), ("Endpoint", 14)]
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
        e = tk.Entry(
            parent,
            font=("Consolas", 9),
            fg=TEXT,
            bg=BG,
            insertbackground=TEXT,
            relief="flat",
            highlightbackground=BORDER,
            highlightthickness=1,
            width=width
        )
        return e

    def _add_card(self, host, idx):
        card = HostCard(self.grid_f, host, self)
        r, c = divmod(idx, 3)
        pad_l = (0, 5) if c == 0 else (5, 5) if c == 1 else (5, 0)
        card.grid(row=r, column=c, sticky="nsew", padx=pad_l, pady=(0, 10))
        card._original_grid_info = card.grid_info()  # ← stamp it
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
        self.ping_all_btn.config(state="disabled", bg=BORDER, fg=TEXT_DIM, cursor="")
        self._set_status("Pinging all hosts…", YELLOW)
        for c in active:
            c.set_pinging()
        self.misc._ping_all()
        threading.Thread(target=self._ping_thread, args=(active,), daemon=True).start()

    def _ping_all_safe(self):
        if getattr(self, "_pinging_all", False):
            return

        try:
            self._ping_all()
        finally:
            self._pinging_all = False

    def _ping_thread(self, cards):
        done = [0]
        lock = threading.Lock()
        
        def one(card):
            target   = (card.host.get("ip") or "").strip().lower()
            port_val = (card.host.get("port") or "").strip()
            ep       = (card.host.get("endpoint") or "").strip()
            
            is_raw_ip  = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target))
            has_alpha  = bool(re.search(r"[a-z]", target))
            is_domain  = has_alpha and not is_raw_ip

            if is_domain:
                active_port = port_val if port_val else "443"
                
                success_count = 0
                total_time = 0
                valid_times_count = 0
                last_http_result = {}

                # 10x packet loop simulation over HTTP
                for idx in range(PING_COUNT):
                    http_result = check_http(target, active_port, ep)
                    last_http_result = http_result
                    
                    is_ok = http_result.get("status") == "SUCCESS" or "200" in str(http_result.get("status_code", ""))
                    
                    if is_ok:
                        success_count += 1
                        r_time_str = http_result.get("response_time", "").replace("ms", "").strip()
                        if r_time_str.isdigit():
                            total_time += int(r_time_str)
                            valid_times_count += 1
                    
                    self.after(0, card._update_dot, idx, is_ok)

                # Compute loop summary details
                loss_pct = int(((PING_COUNT - success_count) / PING_COUNT) * 100)
                true_avg_ms = f"{int(total_time / valid_times_count)}ms" if valid_times_count > 0 else "—"

                if success_count > 0:
                    # Header metrics setup
                    self.after(0, card.update_result, {
                        "status": "UP", 
                        "avg": "—", 
                        "loss": loss_pct, 
                        "recv": success_count
                    })
                    
                    # Clean label match for the PORT widget column
                    self.after(0, card._update_port_status, {
                        "status": "OPEN", 
                        "response_time": "Open" 
                    })
                    
                    # Direct data-to-label alignment for the HTTP/S column
                    status_code = last_http_result.get("status_code", "200")
                    protocol = last_http_result.get("protocol", "HTTPS")
                    self.after(0, card._update_http_status, {
                        "status": "OK",
                        "status_code": f"{status_code} ({true_avg_ms})", 
                        "protocol": protocol,
                        "response_time": true_avg_ms
                    })
                else:
                    port_result = check_port(target, active_port)
                    self.after(0, card._update_port_status, port_result)
                    self.after(0, card.update_result, {
                        "status": "DOWN", 
                        "avg": "—", 
                        "loss": 100, 
                        "recv": 0
                    })
            
            else:
                # Fallback standard pipeline logic for raw IP targets
                def on_dot(idx, success):
                    self.after(0, card._update_dot, idx, success)
                
                res = ping_host(target, PING_COUNT, dot_callback=on_dot)
                self.after(0, card.update_result, res)
                
                if port_val:
                    port_result = check_port(target, port_val)
                    self.after(0, card._update_port_status, port_result)
                
                self.after(0, card._update_http_status, {
                    "status": "EMPTY", "response_time": "—",
                    "status_code": "—", "protocol": "—"
                })
            
            with lock:
                done[0] += 1
                if done[0] == len(cards):
                    self.after(0, self._ping_done)

        for c in cards:
            threading.Thread(target=one, args=(c,), daemon=True).start()

    def _ping_done(self):
        self._running = False
        self.ping_all_btn.config(state="normal", bg=ACCENT, fg=BG, cursor="hand2")
        now = datetime.datetime.now().strftime("%H:%M:%S")
        self._set_status(f"Last run: {now}", TEXT_DIM)
        if os.path.exists(LOG_PATH):
            self.log_lbl.config(text="", fg=ORANGE)

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
            self.bind("<Escape>", lambda _: self._exit_fullscreen())
        else:
            self.after(100, self._dark_titlebar)

    def _exit_fullscreen(self):
        self.attributes("-fullscreen", False)
        self.after(100, self._dark_titlebar)

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
        vm, ip, phys, sys_n, port, endpoint = [
            "" if v == defaults[i] else v for i, v in enumerate(vals)
        ]
        if ip:
            cleaned_ip = clean_host(ip)
            if not is_valid_host(cleaned_ip):
                self._set_status("Invalid IP format", RED)
                return
            ip = cleaned_ip
        host = {
            "vm_name":       vm or f"VM {len(self.cards)+1:02d}",
            "ip":            ip,
            "physical_name": phys,
            "system_name":   sys_n,
            "port":          port,
            "endpoint":      endpoint,
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