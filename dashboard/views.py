import os
import subprocess
import paramiko
import re
import requests
import json
import math
from django.shortcuts import render
from requests.auth import HTTPBasicAuth
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from collections import Counter, deque
import matplotlib.pyplot as plt
import io
import base64


def home(request):
    return render(request, 'dashboard/home.html')

def devices(request):
    try:
        # Fetch switches
        dev_resp = requests.get("http://127.0.0.1:8181/onos/v1/devices", auth=('onos', 'rocks'))
        devices = dev_resp.json().get("devices", [])

        # Fetch hosts
        host_resp = requests.get("http://127.0.0.1:8181/onos/v1/hosts", auth=('onos', 'rocks'))
        hosts = host_resp.json().get("hosts", [])

    except Exception as e:
        devices = []
        hosts = []
        
    return render(request, 'dashboard/devices.html', {
        'devices': devices,
        'hosts': hosts
    })
def calculate_entropy(data):
    if not data:
        return 0.0
    count = Counter(data)
    total = sum(count.values())
    entropy = -sum((freq / total) * math.log2(freq / total) for freq in count.values())
    if round(entropy,4) == -0.0:
        entropy = 0.0
    return round(entropy, 4)


def ping_statistics_view(request):
    src_ips = []
    ttls = []
    lengths = []
    protocols = []
    debug_lines = []
    detected_protocol = None

    try:
        # Run tcpdump with stdout and stderr capture
        result = subprocess.run(
            ['timeout', '10', 'tcpdump', '-i', 'any', '-nn', '-c', '200', 'icmp or tcp[tcpflags] & tcp-syn != 0'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # Append both stdout and stderr to debug
        debug_lines.append("[STDOUT]")
        debug_lines.extend(result.stdout.splitlines())
        debug_lines.append("[STDERR]")
        debug_lines.extend(result.stderr.splitlines())

        lines = result.stdout.splitlines()

        for line in lines:
            line = line.strip()

            # Handle ICMP
            if "ICMP echo request" in line:
                detected_protocol = "ICMP"

                match = re.search(r'IP (\d+\.\d+\.\d+\.\d+) >', line)
                if match:
                    src_ips.append(match.group(1))

                ttl_match = re.search(r'TTL=(\d+)', line)
                if ttl_match:
                    ttls.append(ttl_match.group(1))

                length_match = re.search(r'length (\d+)', line)
                if length_match:
                    lengths.append(length_match.group(1))

                protocols.append("1")  # ICMP

            # Handle TCP SYN
            elif "Flags [S]" in line:
                detected_protocol = "TCP"

                match = re.search(r'IP (\d+\.\d+\.\d+\.\d+)\.\d+ >', line)
                if match:
                    src_ips.append(match.group(1))

                ttl_match = re.search(r'TTL=(\d+)', line)
                if ttl_match:
                    ttls.append(ttl_match.group(1))

                length_match = re.search(r'length (\d+)', line)
                if length_match:
                    lengths.append(length_match.group(1))

                protocols.append("6")  # TCP

    except Exception as e:
        debug_lines.append(f"[ERROR] {str(e)}")

    entropy_scores = {
        "Source IP": calculate_entropy(src_ips),
        "TTL": calculate_entropy(ttls),
        "Packet Length": calculate_entropy(lengths),
        "Protocol": calculate_entropy(protocols),
    }

    flood_detected = any(ent < 1.0 for ent in entropy_scores.values())

    return render(request, 'dashboard/ping_statistics.html', {
        'sources': sorted(set(src_ips)),
        'debug_output': "\n".join(debug_lines) if debug_lines else "No packets captured.",
        'entropy_scores': entropy_scores,
        'flood_detected': flood_detected,
        'protocol': detected_protocol or "None Detected"
    })

entropy_history = deque(maxlen=10)
K = 1.0  # Chebyshev constant

def get_source_ips_from_logs_or_api():
    try:
        result = subprocess.run(
            ['timeout', '10', 'tcpdump', '-i', 'any', '-nn', '-c', '200', 'icmp or tcp[tcpflags] & tcp-syn != 0'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        lines = result.stdout.splitlines()
        ips = []

        for line in lines:
            if "ICMP echo request" in line:
                match = re.search(r'IP (\d+\.\d+\.\d+\.\d+) >', line)
                if match:
                    ips.append(match.group(1))
            elif "Flags [S]" in line:
                match = re.search(r'IP (\d+\.\d+\.\d+\.\d+)\.\d+ >', line)
                if match:
                    ips.append(match.group(1))

        return ips
    except Exception as e:
        print(f"Error running tcpdump: {e}")
        return []
def ddos_detection_view(request):
    source_ips = get_source_ips_from_logs_or_api()

    entropy = calculate_entropy(source_ips)
    num_unique = len(set(source_ips))
    normalized_entropy = round(entropy / math.log2(num_unique), 4) if num_unique > 1 else 0.0

    entropy_history.append(normalized_entropy)

    if len(entropy_history) >= 3:
        mean = sum(entropy_history) / len(entropy_history)
        std_dev = math.sqrt(sum((e - mean) ** 2 for e in entropy_history) / len(entropy_history))
        threshold = round(mean - K * std_dev, 4)
    else:
        threshold = 0.0

    is_alert = normalized_entropy < threshold if threshold > 0 else False

    context = {
        "entropy": normalized_entropy,
        "threshold": threshold,
        "is_alert": is_alert,
        "source_ips": Counter(source_ips).most_common()
    }

    return render(request, "dashboard/ddos_detection.html", context)

entropy_history = []
threshold_history = []

def dynamic_threshold(history, window_size=5, alpha=0.01):
    if len(history) < window_size:
        return 0.9999  # default high value initially
    window = history[-window_size:]
    mean = sum(window) / window_size
    return round(mean + alpha, 4)

def entropy_graph(request):
    try:
        result = subprocess.run(
            ['timeout', '10', 'tcpdump', '-i', 'any', '-nn', '-c', '1500', 'icmp or tcp[tcpflags] & tcp-syn != 0'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        lines = result.stdout.split('\n')
        source_ips = []
        for line in lines:
            parts = line.split()
            if len(parts) > 2 and parts[1].count('.') == 3:
                ip = parts[1].split('.')[0]
                source_ips.append(ip)

        entropy = calculate_entropy(source_ips)
        entropy_history.append(entropy)

        threshold = dynamic_threshold(entropy_history)
        threshold_history.append(threshold)

        # Create the graph with two subplots
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

        ax1.plot(entropy_history, marker='o', color='blue')
        ax1.set_title('Entropy over Time')
        ax1.set_xlabel('Time (intervals)')
        ax1.set_ylabel('Entropy')

        ax2.plot(threshold_history, marker='s', color='red')
        ax2.set_title('Dynamic Threshold over Time')
        ax2.set_xlabel('Time (intervals)')
        ax2.set_ylabel('Threshold')

        # Save to buffer
        buf = io.BytesIO()
        plt.tight_layout()
        plt.savefig(buf, format='png')
        buf.seek(0)
        image_base64 = base64.b64encode(buf.read()).decode('utf-8')
        buf.close()

        context = {
            'image_base64': image_base64,
            'latest_entropy': entropy,
            'latest_threshold': threshold,
        }

        return render(request, 'dashboard/entropy_graph.html', context)

    except Exception as e:
        return render(request, 'dashboard/entropy_graph.html', {'error': str(e)})

def applications(request):
    url = 'http://127.0.0.1:8181/onos/v1/applications'  # change if ONOS IP differs
    try:
        response = requests.get(url, auth=HTTPBasicAuth('onos', 'rocks'))
        response.raise_for_status()
        apps = response.json().get('applications', [])
    except requests.RequestException as e:
        apps = []
    return render(request, 'dashboard/applications.html', {'applications': apps})

def activity_log(request):
    log_lines = ["Unable to fetch logs."]
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(hostname="localhost", port=8101, username="karaf", password="karaf")

        stdin, stdout, stderr = ssh.exec_command("log:display")
        raw_logs = stdout.read().decode() or stderr.read().decode()
        ssh.close()

        log_lines = raw_logs.strip().splitlines()
    except Exception as e:
        log_lines = [f"Error connecting to ONOS: {str(e)}"]

    return render(request, 'dashboard/activity_log.html', {'log_lines': log_lines})



def ports(request):
    ports_data = {}
    ip = "127.0.0.1"  # Hardcoded ONOS IP since it's running locally

    try:
        devices_url = f"http://{ip}:8181/onos/v1/devices"
        devices_response = requests.get(devices_url, auth=HTTPBasicAuth('onos', 'rocks'))
        devices_response.raise_for_status()

        devices = devices_response.json().get('devices', [])
        for device in devices:
            device_id = device.get('id')
            port_url = f"http://{ip}:8181/onos/v1/devices/{device_id}/ports"
            port_response = requests.get(port_url, auth=HTTPBasicAuth('onos', 'rocks'))
            port_response.raise_for_status()

            port_info = port_response.json().get('ports', [])
            ports_data[device_id] = port_info

    except requests.RequestException as e:
        ports_data = {}

    return render(request, 'dashboard/ports.html', {'ports': ports_data})

def flows(request):
    ip = "127.0.0.1"  # ONOS controller IP
    flows_data = {}

    try:
        devices_url = f"http://{ip}:8181/onos/v1/devices"
        devices_response = requests.get(devices_url, auth=HTTPBasicAuth('onos', 'rocks'))
        devices_response.raise_for_status()

        devices = devices_response.json().get('devices', [])
        for device in devices:
            device_id = device.get('id')
            flow_url = f"http://{ip}:8181/onos/v1/flows/{device_id}"
            flow_response = requests.get(flow_url, auth=HTTPBasicAuth('onos', 'rocks'))
            flow_response.raise_for_status()

            flows = flow_response.json().get('flows', [])
            flows_data[device_id] = flows

    except requests.RequestException as e:
        flows_data = {}

    return render(request, 'dashboard/flows.html', {'flows': flows_data})

def download_flows(request):
    ip = "127.0.0.1"
    all_flows = {}

    try:
        devices_url = f"http://{ip}:8181/onos/v1/devices"
        response = requests.get(devices_url, auth=HTTPBasicAuth('onos', 'rocks'))
        response.raise_for_status()
        devices = response.json().get('devices', [])

        for device in devices:
            device_id = device.get('id')
            flow_url = f"http://{ip}:8181/onos/v1/flows/{device_id}"
            flows_response = requests.get(flow_url, auth=HTTPBasicAuth('onos', 'rocks'))
            flows_response.raise_for_status()
            flows = flows_response.json().get('flows', [])
            all_flows[device_id] = flows

    except requests.RequestException:
        all_flows = {}

    return JsonResponse(all_flows, safe=False, json_dumps_params={'indent': 2})

def networkconfiguration(request):
    ip = "127.0.0.1"
    config_data = {}

    try:
        url = f"http://{ip}:8181/onos/v1/network/configuration"
        response = requests.get(url, auth=HTTPBasicAuth('onos', 'rocks'))
        response.raise_for_status()
        raw_data = response.json()

        devices = {}
        for device_id, device_info in raw_data.get('devices', {}).items():
            # No 'basic', access classifiers directly
            classifiers = device_info.get('classifiers', [])
            simplified = [
                {
                    "ethernet_type": item.get("ethernet-type", ""),
                    "target_queue": item.get("target-queue", "")
                }
                for item in classifiers
            ]
            devices[device_id] = simplified

        config_data["devices"] = devices

    except requests.RequestException as e:
        config_data = {}

    return render(request, 'dashboard/networkconfiguration.html', {'config': config_data})




def download_networkconfiguration(request):
    ip = "127.0.0.1"
    config_data = {}

    try:
        url = f"http://{ip}:8181/onos/v1/network/configuration"
        response = requests.get(url, auth=HTTPBasicAuth('onos', 'rocks'))
        response.raise_for_status()
        config_data = response.json()
    except requests.RequestException:
        config_data = {}

    return JsonResponse(config_data, safe=False, json_dumps_params={'indent': 2})


@csrf_exempt
def port_control(request):
    context = {}

    if request.method == "POST":
        device_id = request.POST.get("device_id")
        port_number = request.POST.get("port_number")
        action = request.POST.get("action")  # 'enable' or 'disable'

        karaf_host = "localhost"
        karaf_port = 8101
        karaf_user = "karaf"
        karaf_pass = "karaf"

        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=karaf_host, port=karaf_port, username=karaf_user, password=karaf_pass)

            command = f"portstate {device_id} {port_number} {action}"
            stdin, stdout, stderr = ssh.exec_command(command)

            output = stdout.read().decode().strip()
            error = stderr.read().decode().strip()
            ssh.close()

            context["status"] = "Success" if not error else "Failed"
            context["output"] = output
            context["error"] = error
            context["command"] = command

        except Exception as e:
            context["status"] = "Error"
            context["error"] = str(e)

    return render(request, "dashboard/port_control.html", context)


@csrf_exempt
def block_traffic(request):
    from requests.auth import HTTPBasicAuth
    import requests, json

    controller = "127.0.0.1:8181"
    auth = HTTPBasicAuth("onos", "rocks")

    # Get devices and hosts
    device_ids = []
    host_ips = []

    try:
        dev_resp = requests.get(f"http://{controller}/onos/v1/devices", auth=auth).json()
        device_ids = [dev["id"] for dev in dev_resp["devices"]]

        host_resp = requests.get(f"http://{controller}/onos/v1/hosts", auth=auth).json()
        host_ips = [host["ipAddresses"][0] for host in host_resp["hosts"]]
    except Exception as e:
        return JsonResponse({"error": str(e)})

    context = {
        "devices": device_ids,
        "hosts": host_ips,
        "response": None
    }

    if request.method == "POST":
        host_ip = request.POST.get("host")
        device_id = request.POST.get("device")
        action = request.POST.get("action")
        if host_ip == "other":
            host_ip = request.POST.get("other_host")

        flow_url = f"http://{controller}/onos/v1/flows/{device_id}"
        flow = {
            "priority": 40000,
            "isPermanent": True,
            "timeout": 0,
            "deviceId": device_id,
            "treatment": {} if action == "block" else {"instructions": [{"type": "OUTPUT", "port": "NORMAL"}]},
            "selector": {
                "criteria": [
                    {"type": "ETH_TYPE", "ethType": "0x800"},
                    {"type": "IPV4_SRC", "ip": f"{host_ip}/32"}
                ]
            }
        }

        try:
            # BLOCK: Install drop flow
            if action == "block":
                flow["treatment"] = {"instructions": []}  # No output means drop
                resp = requests.post(
                    flow_url,
                    data=json.dumps(flow),
                    auth=auth,
                    headers={"Content-Type": "application/json"}
                )
                context["response"] = {"status": "Blocked", "message": resp.text}
            else:
                # Unblocking by removing flows matching criteria
                flows_resp = requests.get(flow_url, auth=auth).json()
                removed = 0
                for f in flows_resp.get("flows", []):
                    match_ip = any(c.get("type") == "IPV4_SRC" and c.get("ip") == f"{host_ip}/32" for c in f.get("selector", {}).get("criteria", []))
                    if match_ip:
                        flow_id = f["id"]
                        delete_url = f"{flow_url}/{flow_id}"
                        requests.delete(delete_url, auth=auth)
                        removed += 1
                context["response"] = {"status": "Unblocked", "message": f"Removed {removed} flow(s)."}

        except Exception as e:
            context["response"] = {"status": "Error", "message": str(e)}

    return render(request, "dashboard/block_traffic.html", context)



