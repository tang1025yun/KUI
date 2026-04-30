# -*- coding: utf-8 -*-
import urllib.request
import json
import os
import time
import subprocess
import re
import sys

# 强制系统编码锁
if sys.stdout.encoding != 'UTF-8':
    try: sys.stdout.reconfigure(encoding='utf-8')
    except Exception: pass

CONF_FILE = "/opt/kui/config.json"
SINGBOX_CONF_PATH = "/etc/sing-box/config.json"

try:
    with open(CONF_FILE, 'r') as f:
        env = json.load(f)
except Exception:
    print("Failed to read config file.")
    exit(1)

API_URL = env["api_url"]
REPORT_URL = env["report_url"]
VPS_IP = env["ip"]
TOKEN = env["token"]

HEADERS = {'Content-Type': 'application/json', 'Authorization': TOKEN, 'User-Agent': 'KUI-Agent/1.3.10'}
last_reported_bytes = {}
argo_tunnels = {}
prev_cpu_total = prev_cpu_idle = prev_rx = prev_tx = 0

# ===============================================
# 🚀 融合 fscarmen 脚本：全系防火墙智能击穿
# ===============================================
def ensure_firewall_open(port):
    port = str(port)
    for protocol in ["tcp", "udp"]:
        cmds = [
            f"iptables -C INPUT -p {protocol} --dport {port} -j ACCEPT 2>/dev/null || iptables -I INPUT -p {protocol} --dport {port} -j ACCEPT",
            f"iptables -C OUTPUT -p {protocol} --sport {port} -j ACCEPT 2>/dev/null || iptables -I OUTPUT -p {protocol} --sport {port} -j ACCEPT",
            f"ip6tables -C INPUT -p {protocol} --dport {port} -j ACCEPT 2>/dev/null || ip6tables -I INPUT -p {protocol} --dport {port} -j ACCEPT",
            f"ip6tables -C OUTPUT -p {protocol} --sport {port} -j ACCEPT 2>/dev/null || ip6tables -I OUTPUT -p {protocol} --sport {port} -j ACCEPT"
        ]
        for cmd in cmds: subprocess.run(cmd, shell=True, stderr=subprocess.DEVNULL)

        if subprocess.run("command -v ufw", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            subprocess.run(f"ufw allow {port}/{protocol} >/dev/null 2>&1", shell=True)

        if subprocess.run("command -v firewall-cmd", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            subprocess.run(f"firewall-cmd --zone=public --add-port={port}/{protocol} >/dev/null 2>&1", shell=True)

def get_port_traffic(port, protocol="tcp"):
    ensure_firewall_open(port)
    try:
        in_bytes = out_bytes = 0
        out_in = subprocess.check_output(f"iptables -nvx -L INPUT | grep 'dpt:{port}'", shell=True).decode()
        in_bytes += sum([int(line.split()[1]) for line in out_in.strip().split('\n') if line])
        out_out = subprocess.check_output(f"iptables -nvx -L OUTPUT | grep 'spt:{port}'", shell=True).decode()
        out_bytes += sum([int(line.split()[1]) for line in out_out.strip().split('\n') if line])
        try:
            out_in6 = subprocess.check_output(f"ip6tables -nvx -L INPUT | grep 'dpt:{port}'", shell=True).decode()
            in_bytes += sum([int(line.split()[1]) for line in out_in6.strip().split('\n') if line])
            out_out6 = subprocess.check_output(f"ip6tables -nvx -L OUTPUT | grep 'spt:{port}'", shell=True).decode()
            out_bytes += sum([int(line.split()[1]) for line in out_out6.strip().split('\n') if line])
        except Exception: pass
        return in_bytes + out_bytes
    except Exception: return 0

# ===============================================
# 核心状态采集与上报
# ===============================================
def get_system_status():
    global prev_cpu_total, prev_cpu_idle, prev_rx, prev_tx
    stats = {"cpu": 0, "mem": 0, "disk": 0, "uptime": "Unknown", "load": "0.00", "net_in_speed": 0, "net_out_speed": 0}
    try:
        with open('/proc/stat', 'r') as f:
            for line in f:
                if line.startswith('cpu '):
                    p = [float(x) for x in line.split()[1:]]
                    idle, total = p[3] + p[4], sum(p)
                    if prev_cpu_total > 0 and (total - prev_cpu_total) > 0:
                        stats["cpu"] = int(100.0 * (1.0 - (idle - prev_cpu_idle) / (total - prev_cpu_total)))
                    prev_cpu_total, prev_cpu_idle = total, idle
                    break
    except Exception: pass
    try:
        with open('/proc/meminfo', 'r') as f: mem = f.read()
        t = re.search(r'MemTotal:\s+(\d+)', mem)
        a = re.search(r'MemAvailable:\s+(\d+)', mem)
        if t and a: stats["mem"] = int(((float(t.group(1)) - float(a.group(1))) / float(t.group(1))) * 100)
    except Exception: pass
    return stats

def report_status(current_nodes, argo_urls):
    global last_reported_bytes
    status = get_system_status()
    status["ip"] = VPS_IP
    status["argo_urls"] = argo_urls
    deltas = []
    current_ids = set()

    for node in current_nodes:
        nid, port = node["id"], node["port"]
        current_ids.add(nid)
        proto = "udp" if node["protocol"] in ["Hysteria2", "TUIC"] else "tcp"
        current_bytes = get_port_traffic(port, proto)
        
        delta = current_bytes - last_reported_bytes.get(nid, current_bytes)
        if delta > 0: deltas.append({ "id": nid, "delta_bytes": delta })
        last_reported_bytes[nid] = current_bytes

    last_reported_bytes = {k: v for k, v in last_reported_bytes.items() if k in current_ids}
    status["node_traffic"] = deltas

    try: urllib.request.urlopen(urllib.request.Request(REPORT_URL, data=json.dumps(status).encode(), headers=HEADERS), timeout=5)
    except Exception: pass

# ===============================================
# Argo 隧道高可用守护
# ===============================================
def ensure_cloudflared():
    if not os.path.exists("/usr/local/bin/cloudflared"):
        os.system("curl -L -o /usr/local/bin/cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 && chmod +x /usr/local/bin/cloudflared")

def process_argo_nodes(configs):
    argo_urls = []
    expected_ports = [str(n['port']) for n in configs if n.get('protocol') == 'VLESS-Argo']
    
    for port in expected_ports:
        if port not in argo_tunnels:
            ensure_cloudflared()
            cmd = ["/usr/local/bin/cloudflared", "tunnel", "--edge-ip-version", "auto", "--no-autoupdate", "--url", f"http://127.0.0.1:{port}"]
            p = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.DEVNULL, text=True)
            url = None
            start_t = time.time()
            while time.time() - start_t < 15:
                line = p.stderr.readline()
                if not line: break
                m = re.search(r'https://([a-zA-Z0-9-]+\.trycloudflare\.com)', line)
                if m: url = m.group(1); break
            if url: argo_tunnels[port] = {"proc": p, "url": url}
        if port in argo_tunnels: argo_urls.append({"id": [n['id'] for n in configs if str(n['port'])==port][0], "url": argo_tunnels[port]["url"]})
            
    for port in list(argo_tunnels.keys()):
        if port not in expected_ports:
            argo_tunnels[port]["proc"].terminate()
            del argo_tunnels[port]
            
    return argo_urls

# ===============================================
# 🚀 融合 fscarmen 脚本：Sing-box 全协议标准生成
# ===============================================
def build_singbox_config(nodes):
    singbox_config = {
        "log": {"level": "warn"},
        "inbounds": [],
        "outbounds": [{"type": "direct", "tag": "direct-out"}],
        "route": {"rules": []}
    }
    active_certs = []

    for node in nodes:
        in_tag, proto, port = f"in-{node['id']}", node["protocol"], int(node["port"])
        
        if proto == "VLESS":
            singbox_config["inbounds"].append({"type": "vless", "tag": in_tag, "listen": "::", "listen_port": port, "users": [{"uuid": node["uuid"]}]})
            
        elif proto == "Reality":
            singbox_config["inbounds"].append({
                "type": "vless", "tag": in_tag, "listen": "::", "listen_port": port,
                "users": [{"uuid": node["uuid"], "flow": "xtls-rprx-vision"}],
                "tls": {
                    "enabled": True, "server_name": node["sni"],
                    "reality": {"enabled": True, "handshake": {"server": node["sni"], "server_port": 443}, "private_key": node["private_key"], "short_id": [node["short_id"]]}
                }
            })

        elif proto in ["Hysteria2", "TUIC"]:
            cert_path, key_path = f"/opt/kui/cert_{node['id']}.pem", f"/opt/kui/key_{node['id']}.pem"
            
            # 🚀 完全复刻 fscarmen 的默认域
            sni = node.get("sni")
            if not sni:
                sni = "addons.mozilla.org"
                
            active_certs.extend([f"cert_{node['id']}.pem", f"key_{node['id']}.pem"])

            if not os.path.exists(cert_path):
                # 🚀 完全复刻 fscarmen ssl_certificate 核心：注入 SAN 扩展，防现代客户端握手失败
                parts = sni.split('.')
                cn = f"{parts[-2]}.{parts[-1]}" if len(parts) >= 2 else sni
                conf_path = f"/opt/kui/cert_{node['id']}.conf"
                
                conf_content = f"""[req]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = {cn}

[v3_req]
subjectAltName = @alt_names

[alt_names]
DNS = {sni}
"""
                with open(conf_path, "w") as f:
                    f.write(conf_content)
                
                os.system(f"openssl ecparam -genkey -name prime256v1 -out {key_path} >/dev/null 2>&1")
                os.system(f"openssl req -new -x509 -days 36500 -key {key_path} -out {cert_path} -config {conf_path} -extensions v3_req >/dev/null 2>&1")
                os.system(f"chmod 644 {cert_path} {key_path}")
                try: os.remove(conf_path)
                except Exception: pass

            if proto == "Hysteria2":
                singbox_config["inbounds"].append({"type": "hysteria2", "tag": in_tag, "listen": "::", "listen_port": port, "users": [{"password": node["uuid"]}], "tls": {"enabled": True, "alpn": ["h3"], "certificate_path": cert_path, "key_path": key_path}})
            elif proto == "TUIC":
                singbox_config["inbounds"].append({"type": "tuic", "tag": in_tag, "listen": "::", "listen_port": port, "users": [{"uuid": node["uuid"], "password": node["private_key"]}], "tls": {"enabled": True, "alpn": ["h3"], "certificate_path": cert_path, "key_path": key_path}})

        elif proto == "VLESS-Argo":
            singbox_config["inbounds"].append({"type": "vless", "tag": in_tag, "listen": "127.0.0.1", "listen_port": port, "users": [{"uuid": node["uuid"]}], "transport": {"type": "ws", "path": "/"}})
            
        elif proto == "Socks5":
            singbox_config["inbounds"].append({"type": "socks", "tag": in_tag, "listen": "::", "listen_port": port, "users": [{"username": node["uuid"], "password": node["private_key"]}]})
        
        elif proto == "dokodemo-door":
            singbox_config["inbounds"].append({ "type": "direct", "tag": in_tag, "listen": "::", "listen_port": port })
            out_tag = f"out-{node['id']}"
            if node.get("relay_type") == "internal" and node.get("chain_target"):
                t = node["chain_target"]
                outbound = { "type": t["protocol"].lower(), "tag": out_tag, "server": t["ip"], "server_port": int(t["port"]), "uuid": t["uuid"] }
                if t["protocol"] == "Reality":
                    outbound["tls"] = { "enabled": True, "server_name": t["sni"], "reality": { "enabled": True, "public_key": t["public_key"], "short_id": t["short_id"] } }
                singbox_config["outbounds"].append(outbound)
            else:
                singbox_config["outbounds"].append({ "type": "direct", "tag": out_tag, "override_address": node["target_ip"], "override_port": int(node["target_port"]) })
            singbox_config["route"]["rules"].append({ "inbound": [in_tag], "outbound": out_tag })

    new_config_str = json.dumps(singbox_config, indent=2)
    old_config_str = ""
    if os.path.exists(SINGBOX_CONF_PATH):
        with open(SINGBOX_CONF_PATH, "r") as f: old_config_str = f.read()

    if new_config_str != old_config_str:
        with open(SINGBOX_CONF_PATH, "w") as f: f.write(new_config_str)
        # 智能重启机制兼容
        if os.path.exists("/sbin/openrc-run") or os.path.exists("/etc/alpine-release"):
            os.system("rc-service sing-box restart >/dev/null 2>&1")
        else:
            os.system("systemctl restart sing-box >/dev/null 2>&1")

def fetch_and_apply_configs():
    try:
        res = urllib.request.urlopen(urllib.request.Request(f"{API_URL}?ip={VPS_IP}", headers=HEADERS), timeout=10)
        data = json.loads(res.read().decode('utf-8'))
        if data.get("success"):
            nodes = data.get("configs", [])
            build_singbox_config(nodes)
            return nodes
    except Exception: pass
    return None

if __name__ == "__main__":
    current_active_nodes = []
    time.sleep(2)
    while True:
        fetched_nodes = fetch_and_apply_configs()
        if fetched_nodes is not None: current_active_nodes = fetched_nodes
        argo_urls = process_argo_nodes(current_active_nodes)
        report_status(current_active_nodes, argo_urls)
        time.sleep(15)
