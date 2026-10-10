#!/usr/bin/env python3
"""
USBGate - every new USB device is cut off until an administrator approves it
at the machine with their admin username + password. Website = read-only security log.

Run from an ADMIN PowerShell (needed to disable/enable devices):
    python usbgate.py           real USB devices
    python usbgate.py --sim     fake devices (popup + credential check are real)

Optional (recommended) block-before-install policy, so a device is blocked BEFORE it
ever loads a driver (closes the ~1s window a BadUSB keyboard could use):
    reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions" /v DenyUnspecified /t REG_DWORD /d 1 /f
    reg add "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DeviceInstall\\Restrictions" /v AllowInstanceIDs /t REG_DWORD /d 1 /f
    gpupdate /force

Security log:  http://<ip>:5000      Audit file: usbgate_log.jsonl
Env: WEBHOOK_URL (Discord/Slack), TIMEOUT (default 60)
"""
import os, re, sys, time, json, uuid, queue, socket, threading, subprocess, datetime, random
import requests
from flask import Flask, jsonify, render_template_string

SIM = "--sim" in sys.argv
IS_WIN = os.name == "nt"
WEBHOOK = os.environ.get("WEBHOOK_URL", "")
TIMEOUT = int(os.environ.get("TIMEOUT", "60"))
CHILD_WINDOW = 20
HOST = socket.gethostname()
POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
LOGFILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "usbgate_log.jsonl")

pending, log, approved = {}, [], set()
lock = threading.Lock()
popup_q = queue.Queue()
child_until = 0.0
app = Flask(__name__)


# ---------------- log / alert ----------------
def event(kind, msg, dev=None):
    e = {"time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "host": HOST, "event": kind, "msg": msg}
    if dev:
        e.update({k: dev.get(k) for k in ("name", "vid", "serial", "hid")})
    print(f"[{e['time']}] {kind}: {msg}", flush=True)
    with lock:
        log.insert(0, e); del log[500:]
    try:
        with open(LOGFILE, "a") as f:
            f.write(json.dumps(e) + "\n")
    except Exception:
        pass


def alert(msg):
    if WEBHOOK:
        try:
            requests.post(WEBHOOK, json={"content": msg, "text": msg}, timeout=5)
        except Exception as ex:
            print("webhook failed:", ex)


# ---------------- Windows helpers ----------------
def ps(cmd):
    return subprocess.run(["powershell", "-NoProfile", "-Command", cmd],
                          capture_output=True, text=True).stdout.strip()


def run(*args):
    r = subprocess.run(list(args), capture_output=True, text=True)
    return r.returncode == 0


def is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def policy_on():
    try:
        import winreg
        k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, POLICY_KEY)
        return winreg.QueryValueEx(k, "DenyUnspecified")[0] == 1
    except Exception:
        return False


def policy_allow(inst):
    import winreg
    k = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, POLICY_KEY + r"\AllowInstanceIDs", 0, winreg.KEY_SET_VALUE)
    winreg.SetValueEx(k, "ug" + uuid.uuid4().hex, 0, winreg.REG_SZ, inst)


def usb_devices():
    """Top-level physical USB devices currently plugged in."""
    out = ps("Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'USB\\VID_*' } | "
             "Select-Object InstanceId,FriendlyName,Status,Class | ConvertTo-Json -Compress")
    if not out:
        return {}
    data = json.loads(out)
    data = data if isinstance(data, list) else [data]
    return {d["InstanceId"]: d for d in data if "&MI_" not in d["InstanceId"].upper()}


def problem_devices():
    out = ps("Get-PnpDevice -PresentOnly | Where-Object { $_.Status -ne 'OK' } | "
             "Select-Object -ExpandProperty InstanceId")
    return set(out.splitlines()) if out else set()


def looks_hid(inst, cls):
    if (cls or "").lower() in ("hidclass", "keyboard", "mouse"):
        return True
    ids = ps(f"(Get-PnpDeviceProperty -InstanceId '{inst}' -KeyName DEVPKEY_Device_CompatibleIds).Data")
    return "Class_03" in ids


# ---------------- admin credential check ----------------
def verify_admin(user, pw):
    """True only if user/password are valid AND the account is a local Administrator."""
    if not IS_WIN:
        return user == "admin" and pw == "admin"      # non-Windows sim fallback
    import ctypes
    from ctypes import wintypes
    domain = "."
    if "\\" in user:
        domain, user = user.split("\\", 1)
    tok = wintypes.HANDLE()
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    if not adv.LogonUserW(user, domain, pw, 3, 0, ctypes.byref(tok)):   # 3 = NETWORK logon
        return False
    ctypes.windll.kernel32.CloseHandle(tok)
    members = ps("Get-LocalGroupMember -SID S-1-5-32-544 -ErrorAction SilentlyContinue | "
                 "Select-Object -ExpandProperty Name")
    members += "\n" + subprocess.run(["net", "localgroup", "Administrators"],
                                     capture_output=True, text=True).stdout
    names = {ln.strip().lower().split("\\")[-1] for ln in members.splitlines() if ln.strip()}
    return user.lower() in names


# ---------------- core ----------------
def new_device(dev):
    with lock:
        if dev["id"] in pending:
            return
        dev["since"] = time.time()
        pending[dev["id"]] = dev
    tag = "HIGH - keyboard/HID device (possible BadUSB)" if dev["hid"] else "storage/other"
    event("BLOCKED", f"{dev['name']} ({dev['vid']}) serial={dev['serial'] or '-'} [{tag}] via {dev['how']}", dev)
    alert(f":rotating_light: USB blocked on **{HOST}**: {dev['name']} ({dev['vid']}) - {tag}. Admin approval required.")
    popup_q.put(("open", dev))


def decide(dev_id, allow, reason=""):
    global child_until
    with lock:
        dev = pending.pop(dev_id, None)
    if not dev:
        return
    inst = dev.get("inst")
    if allow:
        if inst:
            approved.add(inst)
            child_until = time.time() + CHILD_WINDOW
            if dev["how"] == "policy":
                policy_allow(inst)
                run("pnputil", "/scan-devices")
            else:
                run("pnputil", "/enable-device", inst)
        event("ALLOWED", f"{dev['name']} ({dev['vid']}) approved by administrator {reason}", dev)
        alert(f"USB allowed on {HOST}: {dev['name']} ({dev['vid']}) {reason}")
    else:
        event("DENIED", f"{dev['name']} ({dev['vid']}) {reason or 'denied'} - device stays disabled", dev)
        alert(f"USB denied on {HOST}: {dev['name']} ({dev['vid']}) {reason}")
    popup_q.put(("close", dev_id))


def watcher():
    global child_until
    prev = usb_devices()
    known_problems = problem_devices()
    event("START", f"Trusting {len(prev)} USB devices already connected. "
                   f"Block-before-install policy: {'ON' if policy_on() else 'OFF (disable-on-arrival mode)'}")
    n = 0
    while True:
        try:
            cur = usb_devices()
            for inst in set(cur) - set(prev):
                d = cur[inst]
                if inst in approved:
                    event("RECONNECT", f"Approved device reconnected: {d.get('FriendlyName') or inst}")
                    continue
                if d.get("Status") == "OK":
                    run("pnputil", "/disable-device", inst)   # cut it off immediately
                    how = "disabled on arrival"
                else:
                    how = "policy"
                n += 1
                m = re.search(r"VID_([0-9A-F]{4})&PID_([0-9A-F]{4})", inst, re.I)
                new_device(dict(id=str(n), inst=inst, how=how,
                                vid=f"{m.group(1)}:{m.group(2)}".lower() if m else "?",
                                serial=inst.split("\\")[-1],
                                name=d.get("FriendlyName") or d.get("Class") or "USB device",
                                hid=looks_hid(inst, d.get("Class"))))
            prev = cur
            # let the child parts (disk, volume, HID) of an approved device install
            if time.time() < child_until and policy_on():
                for p in problem_devices() - known_problems:
                    policy_allow(p)
                    known_problems.add(p)
                run("pnputil", "/scan-devices")
        except Exception as ex:
            print("watcher error:", ex, flush=True)
        time.sleep(1)


def reaper():
    while True:
        with lock:
            expired = [k for k, d in pending.items() if time.time() - d["since"] > TIMEOUT]
        for k in expired:
            decide(k, False, "auto-denied: no admin response (timeout)")
        time.sleep(1)


# ---------------- on-screen warning popup ----------------
def run_gui():
    import tkinter as tk
    root = tk.Tk(); root.withdraw()
    wins = {}
    BG, RED, GRN, YEL, FG = "#1a1d24", "#e5484d", "#30a46c", "#e0a800", "#e6e6e6"

    def beep():
        try:
            import winsound
            for _ in range(3):
                winsound.Beep(1200, 180)
        except Exception:
            root.bell()

    def open_popup(dev):
        w = tk.Toplevel(root)
        w.title("USBGate - Security Warning")
        w.attributes("-topmost", True); w.configure(bg=BG); w.resizable(False, False)
        w.protocol("WM_DELETE_WINDOW", lambda: None)
        tk.Label(w, text="⚠  UNKNOWN USB DEVICE BLOCKED", bg=RED, fg="white",
                 font=("Segoe UI", 15, "bold"), padx=24, pady=12).pack(fill="x")
        typ = "KEYBOARD / HID  -  possible BadUSB attack!" if dev["hid"] else "Storage / other"
        tk.Label(w, text=f"Device:  {dev['name']}\nID:      {dev['vid']}\nSerial:  {dev['serial'] or '-'}\nType:    {typ}",
                 bg=BG, fg=FG, justify="left", font=("Consolas", 11), padx=24, pady=12).pack(anchor="w")
        tk.Label(w, text="Administrator credentials are required to allow this device.",
                 bg=BG, fg=YEL, font=("Segoe UI", 10, "bold"), padx=24).pack(anchor="w")

        form = tk.Frame(w, bg=BG, padx=24, pady=8); form.pack(anchor="w")
        tk.Label(form, text="Admin user", bg=BG, fg=FG).grid(row=0, column=0, sticky="w")
        u = tk.Entry(form, width=28); u.grid(row=0, column=1, padx=8, pady=3)
        tk.Label(form, text="Password", bg=BG, fg=FG).grid(row=1, column=0, sticky="w")
        p = tk.Entry(form, width=28, show="•"); p.grid(row=1, column=1, padx=8, pady=3)
        msg = tk.Label(w, text="", bg=BG, fg=RED, font=("Segoe UI", 9, "bold"), padx=24); msg.pack(anchor="w")
        timer = tk.Label(w, text="", bg=BG, fg="#8a8f98", font=("Segoe UI", 9), padx=24); timer.pack(anchor="w")
        tries = {"n": 0}

        def approve(_=None):
            user, pw = u.get().strip(), p.get()
            p.delete(0, "end")
            if user and verify_admin(user, pw):
                decide(dev["id"], True, f"(by {user})")
            else:
                tries["n"] += 1
                msg.config(text=f"Not an administrator or wrong password ({tries['n']}/3)")
                event("ADMIN_FAILED", f"Failed admin approval for {dev['name']} as '{user}'", dev)
                alert(f":warning: Failed admin approval on {HOST} for {dev['name']} as '{user}'")
                if tries["n"] >= 3:
                    decide(dev["id"], False, "denied: 3 failed admin attempts")
        p.bind("<Return>", approve)

        row = tk.Frame(w, bg=BG); row.pack(pady=(8, 18))
        tk.Button(row, text="🛡  Approve (Admin)", command=approve, bg=GRN, fg="white",
                  font=("Segoe UI", 11, "bold"), relief="flat", padx=14, pady=6).pack(side="left", padx=8)
        tk.Button(row, text="Deny", command=lambda: decide(dev["id"], False, "denied at console"),
                  bg=RED, fg="white", font=("Segoe UI", 11, "bold"), relief="flat",
                  padx=26, pady=6).pack(side="left", padx=8)

        def tick():
            if dev["id"] in wins:
                timer.config(text=f"Auto-deny in {max(0, int(TIMEOUT - (time.time() - dev['since'])))}s")
                w.after(1000, tick)
        wins[dev["id"]] = w; tick()
        w.update_idletasks()
        w.geometry(f"+{(w.winfo_screenwidth() - w.winfo_width()) // 2}+{(w.winfo_screenheight() - w.winfo_height()) // 3}")
        w.lift(); w.focus_force(); u.focus_set()
        beep()

    def pump():
        while not popup_q.empty():
            a, d = popup_q.get()
            if a == "open":
                open_popup(d)
            elif d in wins:
                wins.pop(d).destroy()
        root.after(200, pump)

    root.after(200, pump); root.mainloop()


# ---------------- read-only web security log ----------------
PAGE = """<!doctype html><html><head><meta name=viewport content="width=device-width,initial-scale=1">
<title>USBGate Security Log</title><style>
body{font-family:system-ui;background:#0f1115;color:#e6e6e6;padding:16px;max-width:900px;margin:auto}
h1{margin:0}.sub{color:#8a8f98;margin:4px 0 16px}
.card{background:#1a1d24;border-radius:10px;padding:14px;margin-bottom:10px;border-left:4px solid #e0a800}
.hid{border-left-color:#e5484d}.tag{font-size:12px;padding:2px 8px;border-radius:99px;background:#e5484d;margin-left:6px}
.note{color:#e0a800;font-size:13px;margin-top:6px}
table{width:100%;border-collapse:collapse;font-size:13px}td{padding:6px 8px;border-bottom:1px solid #222;vertical-align:top}
.BLOCKED{color:#e0a800}.ALLOWED{color:#30a46c}.DENIED,.ADMIN_FAILED{color:#e5484d}
button{border:0;border-radius:8px;padding:10px 16px;margin-right:8px;background:#3b82f6;color:#fff;cursor:pointer}
</style></head><body>
<h1>USBGate Security Log</h1>
<div class=sub>Host {{host}} · read-only · approval requires administrator credentials at the machine{% if sim %} · SIM MODE{% endif %}</div>
<div id=pending></div>
{% if sim %}<p><button onclick="sim('storage')">Simulate flash drive</button><button onclick="sim('hid')">Simulate BadUSB keyboard</button></p>{% endif %}
<h3>Events</h3><table id=log></table>
<script>
async function refresh(){
 const s=await (await fetch('/api/state')).json();
 document.getElementById('pending').innerHTML=s.pending.length?s.pending.map(d=>`
  <div class="card ${d.hid?'hid':''}"><b>⚠ ${d.name}</b>${d.hid?'<span class=tag>KEYBOARD / HID</span>':''}<br>
  <small>${d.vid} · serial ${d.serial||'-'} · auto-deny in ${d.left}s</small>
  <div class=note>Waiting for administrator at ${s.host}</div></div>`).join('')
  :'<div class=card style="border-left-color:#30a46c">No blocked devices waiting.</div>';
 document.getElementById('log').innerHTML=s.log.map(e=>
  `<tr><td>${e.time}</td><td class="${e.event}"><b>${e.event}</b></td><td>${e.msg}</td></tr>`).join('');
}
async function sim(t){await fetch('/api/simulate/'+t,{method:'POST'});refresh();}
setInterval(refresh,1000);refresh();
</script></body></html>"""


@app.route("/")
def index():
    return render_template_string(PAGE, host=HOST, sim=SIM)


@app.route("/api/state")
def state():
    with lock:
        p = [dict({k: v for k, v in d.items() if k != "inst"},
                  left=max(0, int(TIMEOUT - (time.time() - d["since"])))) for d in pending.values()]
        return jsonify(host=HOST, pending=p, log=list(log))


@app.route("/api/simulate/<kind>", methods=["POST"])
def simulate(kind):
    if not SIM:
        return jsonify(ok=False), 400
    i = str(random.randint(1000, 9999))
    if kind == "hid":
        new_device(dict(id=i, inst=None, how="sim", vid="16c0:047c", serial="", name="Generic Keyboard", hid=True))
    else:
        new_device(dict(id=i, inst=None, how="sim", vid="0781:5567", serial="4C53" + i,
                        name="SanDisk Cruzer Blade", hid=False))
    return jsonify(ok=True)


if __name__ == "__main__":
    if IS_WIN and not SIM and not is_admin():
        print("Run this from an ADMIN PowerShell (right-click PowerShell > Run as administrator).")
        sys.exit(1)
    event("START", f"USBGate started on {HOST} ({'SIM' if SIM else 'live'} mode)")
    if IS_WIN and not SIM:
        threading.Thread(target=watcher, daemon=True).start()
    threading.Thread(target=reaper, daemon=True).start()
    threading.Thread(target=lambda: app.run(host="0.0.0.0", port=5000), daemon=True).start()
    try:
        run_gui()
    except Exception as ex:
        print("No GUI available:", ex)
        while True:
            time.sleep(3600)
