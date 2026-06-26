#!/usr/bin/env python3
import os, json, time, glob, re, subprocess

PINEAP_CFG    = '/etc/pinapple/pineap_config.json'
SSID_POOL     = '/etc/pinapple/ssid_pool.txt'
ALLOW_MAC_F   = '/etc/pinapple/filter_allow_mac.txt'
DENY_MAC_F    = '/etc/pinapple/filter_deny_mac.txt'
ALLOW_SSID_F  = '/etc/pinapple/filter_allow_ssid.txt'
DENY_SSID_F   = '/etc/pinapple/filter_deny_ssid.txt'
PINEAP_LOG    = '/var/log/pinapple/pineap_events.log'
LOOT_DIR      = '/var/log/pinapple/loot'
CAMPAIGNS_DIR = '/var/log/pinapple/campaigns'
MDK4_PID      = '/var/run/pinapple-mdk4.pid'
PMKID_PID     = '/var/run/pinapple-pmkid.pid'
_mdk4_proc    = [None]
_pmkid_proc   = [None]

def sysinfo():
    info = {}
    try:
        r = subprocess.run(['top','-bn1'], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if 'Cpu' in line:
                m = re.search(r'([\d.]+)\s*id', line)
                if m: info['cpu'] = round(100 - float(m.group(1)), 1)
                break
    except: info['cpu'] = 0
    try:
        mem = {}
        with open('/proc/meminfo') as f:
            for line in f:
                k, v = line.split(':')
                mem[k.strip()] = int(v.strip().split()[0])
        total = mem.get('MemTotal', 1); avail = mem.get('MemAvailable', 0)
        info['ram_pct']      = round((total - avail) / total * 100, 1)
        info['ram_mb']       = (total - avail) // 1024
        info['ram_total_mb'] = total // 1024
    except: info['ram_pct'] = 0; info['ram_mb'] = 0; info['ram_total_mb'] = 0
    try:
        r = subprocess.run(['df','-BM','/'], capture_output=True, text=True)
        parts = r.stdout.splitlines()[1].split()
        info['disk_pct']  = int(parts[4].replace('%',''))
        info['disk_used'] = parts[2]; info['disk_free'] = parts[3]
    except: info['disk_pct'] = 0
    try:
        info['temp'] = int(open('/sys/class/thermal/thermal_zone0/temp').read().strip()) // 1000
    except: info['temp'] = 0
    return info

def load_ssid_pool():
    try:
        with open(SSID_POOL) as f:
            return [l.strip() for l in f if l.strip() and not l.startswith('#')]
    except: return []

def save_ssid_pool(ssids):
    os.makedirs('/etc/pinapple', exist_ok=True)
    with open(SSID_POOL, 'w') as f: f.write('\n'.join(ssids))

def load_filter_list(path):
    try:
        with open(path) as f:
            return [l.strip() for l in f if l.strip() and not l.startswith('#')]
    except: return []

def save_filter_list(path, entries):
    os.makedirs('/etc/pinapple', exist_ok=True)
    with open(path, 'w') as f: f.write('\n'.join(entries))

def load_pineap_cfg():
    d = {'mode':'passive','beacon_response':False,'log_probes':True,'auto_add_to_pool':False}
    try:
        with open(PINEAP_CFG) as f: d.update(json.load(f))
    except: pass
    return d

def save_pineap_cfg(cfg):
    os.makedirs('/etc/pinapple', exist_ok=True)
    with open(PINEAP_CFG, 'w') as f: json.dump(cfg, f, indent=2)

def get_pineap_events(n=100):
    events = []
    try:
        r = subprocess.run(['tail','-n',str(n),PINEAP_LOG], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            try: events.append(json.loads(line))
            except: pass
    except: pass
    return list(reversed(events))

def loot_list():
    os.makedirs(LOOT_DIR, exist_ok=True)
    files = []; checked = set()
    for ext in ['*.pcap','*.pcapng','*.hccapx','*.22000','*.cap','*.html','*.csv']:
        for fp in (glob.glob(os.path.join(LOOT_DIR, ext)) + glob.glob('/var/log/pinapple/' + ext)):
            if os.path.isfile(fp) and fp not in checked:
                checked.add(fp); st = os.stat(fp)
                files.append({'name':os.path.basename(fp),'path':fp,'size':st.st_size,
                    'mtime':time.strftime('%Y-%m-%d %H:%M', time.localtime(st.st_mtime)),
                    'ext':os.path.splitext(fp)[1].lstrip('.')})
    return sorted(files, key=lambda x: x['mtime'], reverse=True)

def _proc_running(proc_ref, pid_file):
    if proc_ref[0] and proc_ref[0].poll() is None:
        return True, proc_ref[0].pid
    try:
        pid = int(open(pid_file).read().strip()); os.kill(pid, 0); return True, pid
    except: return False, None

def _kill_proc(proc_ref, pid_file):
    if proc_ref[0] and proc_ref[0].poll() is None:
        proc_ref[0].terminate(); proc_ref[0] = None
    try:
        pid = int(open(pid_file).read().strip()); os.kill(pid, 15)
    except: pass
    try: os.remove(pid_file)
    except: pass
