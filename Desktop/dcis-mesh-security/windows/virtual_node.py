#!/usr/bin/env python3
import paho.mqtt.client as mqtt
import json
import time
import threading
import argparse
import socket
import subprocess
import psutil
import platform
import random
import logging
from collections import defaultdict, deque
from datetime import datetime
import netifaces
import statistics

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DCISVirtualNode:
    def __init__(self, node_id=None, is_pi=False):
        
        self.node_id = node_id or f"virtual_node_{socket.gethostname()}_{int(time.time())}"
        self.is_pi = is_pi
        self.start_time = time.time()
   
        self.node_ip = self.get_real_local_ip()
 
        self.discovered_devices = {}
        self.monitoring_data = deque(maxlen=1000)
        self.network_activity = defaultdict(list)
        self.anomaly_baseline = {}
        self.detected_anomalies = deque(maxlen=100)
  
        self.pending_validations = {}
   
        self.resource_monitor = ResourceMonitor()
      
        self.connection_baseline = defaultdict(int)
        self.port_access_baseline = defaultdict(int)
        self.learning_mode = True
        self.learning_start = time.time()
        self.learning_duration = 300  
      
        self.mqtt_client = mqtt.Client(client_id=f"dcis_node_{self.node_id}")
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_message = self.on_message
        
        self.running = False
        self.threads = []

    def get_real_local_ip(self):
        
        try:
            
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            
            for interface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr['addr']
                        if not ip.startswith('127.'):
                            return ip
            return "127.0.0.1"

    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logging.info(f"Virtual Node {self.node_id} connected to MQTT broker")
           
            subscriptions = [
                f"dcis/nodes/{self.node_id}/validate_request",
                f"dcis/nodes/{self.node_id}/command",
                "dcis/coordinators/+/heartbeat",
                "dcis/esp32/+/status",
                "dcis/attacks/real_time",
                "dcis/defense/+"
            ]
            for topic in subscriptions:
                client.subscribe(topic)
            
          
            self.publish_discovery()
        else:
            logging.error(f"Failed to connect: {rc}")

    def on_message(self, client, userdata, msg):
      
        try:
            topic = msg.topic
            data = json.loads(msg.payload.decode())
            
            if "validate_request" in topic:
                self.handle_validation_request(data)
            elif "command" in topic:
                self.handle_command(data)
            elif "attacks/real_time" in topic:
                self.observe_attack(data)
            elif "defense" in topic:
                self.observe_defense(topic, data)
                
        except Exception as e:
            logging.error(f"Message processing error: {e}")

    def handle_validation_request(self, data):
       
        validation_id = data.get('validation_id')
        threat_data = data.get('threat_data')
        requesting_coordinator = data.get('coordinator')
        
        if not validation_id or not threat_data:
            return
       
        is_valid = self.validate_threat_locally(threat_data)
        
        response = {
            'validation_id': validation_id,
            'node_id': self.node_id,
            'confirmed': is_valid,
            'confidence': self.calculate_confidence(threat_data),
            'timestamp': time.time()
        }
        
        self.mqtt_client.publish(
            f"dcis/coordinators/{requesting_coordinator}/validate_response",
            json.dumps(response),
            qos=1
        )
        
        logging.info(f"Validation response sent: {validation_id} - Confirmed: {is_valid}")

    def validate_threat_locally(self, threat_data):
       
        target = threat_data.get('target')
        attack_type = threat_data.get('attack_type', '')
        
        for anomaly in self.detected_anomalies:
            if anomaly.get('target') == target:
                return True
        
        if target in [d.get('ip') for d in self.discovered_devices.values()]:
            return threat_data.get('confidence', 0) > 0.5
      
        if 'scan' in attack_type.lower():
            if self.check_scanning_activity(target):
                return True
     
        severity = threat_data.get('severity', 'low')
        confidence = threat_data.get('confidence', 0)
        
        if severity in ['critical', 'high'] and confidence > 0.6:
            return True
        elif severity == 'medium' and confidence > 0.7:
            return True
        elif confidence > 0.8:
            return True
        
        return False

    def calculate_confidence(self, threat_data):
        base_confidence = 0.5
        
        if threat_data.get('target') in [a.get('target') for a in self.detected_anomalies]:
            base_confidence += 0.3
        
        severity_weights = {'critical': 0.2, 'high': 0.15, 'medium': 0.1, 'low': 0.05}
        base_confidence += severity_weights.get(threat_data.get('severity', 'low'), 0)
        
        return min(0.95, base_confidence)

    def check_scanning_activity(self, target_ip):
        if target_ip in self.network_activity:
            connections = self.network_activity[target_ip]
            unique_ports = set(c.get('port') for c in connections)
            return len(unique_ports) > 5
        return False

    def observe_attack(self, data):
        attack_type = data.get('threat_type') or data.get('attack_type')
        target = data.get('target')
        
        logging.info(f"Observed attack: {attack_type} on {target}")
        
        if self.learning_mode:
            self.update_baseline_from_attack(data)

    def observe_defense(self, topic, data):
        action = data.get('action')
        threat_id = data.get('threat_id')
        
        logging.info(f"Observed defense: {action} for threat {threat_id}")

    def handle_command(self, data):
        command = data.get('command')
        
        if command == 'increase_monitoring':
            self.increase_monitoring_frequency()
        elif command == 'reset_baseline':
            self.reset_anomaly_baseline()
        elif command == 'report_status':
            self.publish_detailed_status()

    def network_discovery_loop(self):
        while self.running:
            try:
                network_range = self.get_network_range()

                if not network_range or network_range.startswith('127.'):
                    time.sleep(300)
                    continue

                discovered = self.scan_network_range(network_range)
                
                for device_ip, device_info in discovered.items():
                    if device_ip.startswith('127.'):
                        continue
                    
                    if device_ip not in self.discovered_devices:
                        discovery_message = {
                            'node_id': self.node_id,
                            'ip': device_ip,
                            'device_type': device_info.get('device_type', 'unknown'),
                            'open_ports': device_info.get('open_ports', []),
                            'timestamp': time.time()
                        }
                        
                        self.mqtt_client.publish(
                            f"dcis/nodes/{self.node_id}/discovery",
                            json.dumps(discovery_message),
                            qos=1
                        )
                        
                        self.discovered_devices[device_ip] = device_info
                        logging.info(f"Device discovered: {device_ip}")
                
                time.sleep(300)  
                
            except Exception as e:
                logging.error(f"Network discovery error: {e}")
                time.sleep(600)

    def get_network_range(self):
        try:
            gws = netifaces.gateways()
            default_gateway = gws['default'][netifaces.AF_INET][0]
  
            parts = default_gateway.split('.')
            network = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            
            return network
        except:
            return "192.168.0.0/24"  

    def scan_network_range(self, network_range):
        discovered = {}
        
        try:
            base_ip = network_range.split('/')[0]
            base_parts = base_ip.split('.')
         
            for i in random.sample(range(1, 255), min(20, 254)):
                ip = f"{base_parts[0]}.{base_parts[1]}.{base_parts[2]}.{i}"
                
                if ip == self.node_ip:
                    continue
              
                if self.is_host_alive(ip):
                    discovered[ip] = {
                        'device_type': self.identify_device_type(ip),
                        'open_ports': self.quick_port_scan(ip),
                        'discovered_at': time.time()
                    }
        except Exception as e:
            logging.error(f"Scan error: {e}")
        
        return discovered

    def is_host_alive(self, ip):
        try:
            if platform.system() == "Windows":
                cmd = f"ping -n 1 -w 100 {ip}"
            else:
                cmd = f"ping -c 1 -W 1 {ip}"
            
            result = subprocess.run(cmd, shell=True, capture_output=True, timeout=2)
            return result.returncode == 0
        except:
            return False

    def quick_port_scan(self, ip):
        open_ports = []
        common_ports = [22, 23, 80, 443, 1883, 5683, 8080]
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            
            if sock.connect_ex((ip, port)) == 0:
                open_ports.append(port)
            
            sock.close()
        
        return open_ports

    def identify_device_type(self, ip):
        ports = self.quick_port_scan(ip)
        
        if 1883 in ports:
            return 'mqtt_broker'
        elif 5683 in ports:
            return 'coap_device'
        elif 80 in ports or 443 in ports:
            return 'web_device'
        elif 22 in ports:
            return 'ssh_device'
        elif 23 in ports:
            return 'telnet_device'
        else:
            return 'unknown'

    def anomaly_detection_loop(self):
        while self.running:
            try:                
                if self.learning_mode and time.time() - self.learning_start > self.learning_duration:
                    self.learning_mode = False
                    self.finalize_baseline()
                    logging.info("Learning period complete - Baseline established")
  
                connections = self.get_network_connections()
     
                anomalies = self.detect_real_anomalies(connections)
                
                for anomaly in anomalies:
                    self.detected_anomalies.append(anomaly)
 
                    if anomaly['severity'] in ['high', 'critical']:
                        self.report_anomaly(anomaly)
                
                time.sleep(5) 
                
            except Exception as e:
                logging.error(f"Anomaly detection error: {e}")
                time.sleep(10)

    def get_network_connections(self):
        connections = []
        
        try:
            for conn in psutil.net_connections():
                if conn.status == 'ESTABLISHED':
                    connections.append({
                        'local_ip': conn.laddr.ip if conn.laddr else None,
                        'local_port': conn.laddr.port if conn.laddr else None,
                        'remote_ip': conn.raddr.ip if conn.raddr else None,
                        'remote_port': conn.raddr.port if conn.raddr else None,
                        'status': conn.status,
                        'pid': conn.pid
                    })
        except:
            pass
        
        return connections

    def detect_real_anomalies(self, connections):
        anomalies = []
        connection_counts = defaultdict(int)
        port_access_counts = defaultdict(int)
        
        for conn in connections:
            if not conn['remote_ip']:
                continue
                
            remote_ip = conn['remote_ip']
            remote_port = conn['remote_port']

            if remote_ip.startswith('127.'):
                continue
            
            connection_counts[remote_ip] += 1
            port_access_counts[f"{remote_ip}:{remote_port}"] += 1

        if not self.learning_mode:
            for remote_ip, count in connection_counts.items():
                baseline_count = self.connection_baseline.get(remote_ip, 0)
                
                if count > max(20, baseline_count * 3):  
                    anomalies.append({
                        'type': 'HIGH_CONNECTION_COUNT',
                        'source': self.node_ip,
                        'target': remote_ip,
                        'details': f"Connections: {count} (baseline: {baseline_count})",
                        'severity': 'high' if count > 50 else 'medium',
                        'timestamp': time.time()
                    })

            for key, count in port_access_counts.items():
                if key not in self.port_access_baseline and count > 5:
                    remote_ip, port = key.split(':')
                    anomalies.append({
                        'type': 'NEW_CONNECTION_PATTERN',
                        'source': self.node_ip,
                        'target': remote_ip,
                        'details': f"New port access: {port} ({count} connections)",
                        'severity': 'medium',
                        'timestamp': time.time()
                    })
        else:
            for remote_ip, count in connection_counts.items():
                self.connection_baseline[remote_ip] = max(
                    self.connection_baseline[remote_ip], count
                )
            
            for key, count in port_access_counts.items():
                self.port_access_baseline[key] = max(
                    self.port_access_baseline[key], count
                )
        
        return anomalies

    def finalize_baseline(self):
        for key in self.connection_baseline:
            self.connection_baseline[key] = int(self.connection_baseline[key] * 1.2)
        
        for key in self.port_access_baseline:
            self.port_access_baseline[key] = int(self.port_access_baseline[key] * 1.2)
        
        logging.info(f"Baseline finalized: {len(self.connection_baseline)} IPs, "
                    f"{len(self.port_access_baseline)} port patterns")

    def update_baseline_from_attack(self, attack_data):
        target = attack_data.get('target')
        if target and not target.startswith('127.'):
            self.connection_baseline[target] = self.connection_baseline.get(target, 0) + 5

    def report_anomaly(self, anomaly):
        threat_report = {
            'threat_id': f"anomaly_{self.node_id}_{int(time.time())}",
            'node_id': self.node_id,
            'threat_type': anomaly['type'],
            'source': anomaly.get('source'),
            'target': anomaly.get('target'),
            'severity': anomaly['severity'],
            'confidence': 0.7,
            'details': anomaly.get('details', ''),
            'timestamp': time.time()
        }
        
        self.mqtt_client.publish(
            f"dcis/nodes/{self.node_id}/alert",
            json.dumps(threat_report),
            qos=2
        )
        
        logging.info(f"🚨 Anomaly reported: {anomaly['type']} - {anomaly['severity']}")

    def publish_heartbeat(self):
        while self.running:
            try:
                heartbeat = {
                    'node_id': self.node_id,
                    'ip': self.node_ip,
                    'uptime': time.time() - self.start_time,
                    'status': 'active',
                    'learning_mode': self.learning_mode,
                    'discovered_devices': len(self.discovered_devices),
                    'detected_anomalies': len(self.detected_anomalies),
                    'timestamp': time.time(),
                    'metrics': self.resource_monitor.get_metrics()
                }
                
                self.mqtt_client.publish(
                    f"dcis/nodes/{self.node_id}/heartbeat",
                    json.dumps(heartbeat),
                    qos=1
                )
                
                time.sleep(15) 
                
            except Exception as e:
                logging.error(f"Heartbeat error: {e}")
                time.sleep(15)

    def publish_discovery(self):
        discovery_msg = {
            'node_id': self.node_id,
            'ip': self.node_ip,
            'device_type': 'virtual_iot_node',
            'capabilities': ['monitoring', 'validation', 'discovery'],
            'platform': platform.system(),
            'timestamp': time.time()
        }
        
        self.mqtt_client.publish(
            f"dcis/nodes/{self.node_id}/discovery",
            json.dumps(discovery_msg),
            qos=2
        )

    def publish_monitoring_data(self):
        while self.running:
            try:
                monitoring_data = {
                    'node_id': self.node_id,
                    'connections': len(self.get_network_connections()),
                    'discovered_devices': len(self.discovered_devices),
                    'anomalies_detected': len(self.detected_anomalies),
                    'learning_mode': self.learning_mode,
                    'baseline_entries': len(self.connection_baseline),
                    'timestamp': time.time()
                }
                
                self.mqtt_client.publish(
                    f"dcis/nodes/{self.node_id}/monitoring",
                    json.dumps(monitoring_data),
                    qos=0
                )
                
                time.sleep(30) 
                
            except Exception as e:
                logging.error(f"Monitoring publication error: {e}")
                time.sleep(30)

    def increase_monitoring_frequency(self):
        logging.info("Increasing monitoring frequency per coordinator request")

    def reset_anomaly_baseline(self):
        self.connection_baseline.clear()
        self.port_access_baseline.clear()
        self.learning_mode = True
        self.learning_start = time.time()
        logging.info("Anomaly baseline reset - Entering learning mode")

    def publish_detailed_status(self):
        status = {
            'node_id': self.node_id,
            'ip': self.node_ip,
            'uptime': time.time() - self.start_time,
            'discovered_devices': list(self.discovered_devices.keys()),
            'recent_anomalies': list(self.detected_anomalies)[-10:],
            'baseline_size': len(self.connection_baseline),
            'learning_mode': self.learning_mode,
            'resource_metrics': self.resource_monitor.get_metrics(),
            'timestamp': time.time()
        }
        
        self.mqtt_client.publish(
            f"dcis/nodes/{self.node_id}/detailed_status",
            json.dumps(status),
            qos=1
        )

    def get_statistics(self):
        return {
            'node_id': self.node_id,
            'uptime': time.time() - self.start_time,
            'discovered_devices': len(self.discovered_devices),
            'detected_anomalies': len(self.detected_anomalies),
            'monitoring_entries': len(self.monitoring_data),
            'baseline_connections': len(self.connection_baseline),
            'baseline_ports': len(self.port_access_baseline),
            'learning_mode': self.learning_mode
        }

    def start(self, broker_host='192.168.0.221', broker_port=1883):
        self.running = True
        
        try:
            self.mqtt_client.connect(broker_host, broker_port, 60)
            self.mqtt_client.loop_start()
            
            threads = [
                threading.Thread(target=self.network_discovery_loop),
                threading.Thread(target=self.anomaly_detection_loop),
                threading.Thread(target=self.publish_heartbeat),
                threading.Thread(target=self.publish_monitoring_data)
            ]
            
            for thread in threads:
                thread.start()
                self.threads.append(thread)

            self.resource_monitor.start()
            
            logging.info(f"🚀 Virtual Node {self.node_id} started")
            logging.info(f"   IP: {self.node_ip}")
            logging.info(f"   Platform: {platform.system()}")
            logging.info(f"   Learning Mode: {self.learning_mode}")
            
        except Exception as e:
            logging.error(f"Failed to start: {e}")
            self.running = False

    def stop(self):
        self.running = False

        for thread in self.threads:
            thread.join(timeout=5)
      
        self.resource_monitor.stop()
        
        stats = self.get_statistics()
        stats['status'] = 'stopped'
        
        self.mqtt_client.publish(
            f"dcis/nodes/{self.node_id}/status",
            json.dumps(stats),
            qos=2
        )
        
        self.mqtt_client.loop_stop()
        self.mqtt_client.disconnect()
        
        logging.info(f"Virtual Node stopped - Anomalies detected: {len(self.detected_anomalies)}")


class ResourceMonitor:
    def __init__(self):
        self.running = False
        self.metrics = {}
        self.monitor_thread = None

    def start(self):
        self.running = True
        self.monitor_thread = threading.Thread(target=self.monitor_loop)
        self.monitor_thread.start()

    def monitor_loop(self):
        while self.running:
            try:
                self.metrics = {
                    'cpu_percent': psutil.cpu_percent(interval=0.1),
                    'memory_percent': psutil.virtual_memory().percent,
                    'memory_mb': psutil.virtual_memory().used / (1024 * 1024),
                    'network_connections': len(psutil.net_connections()),
                    'disk_usage_percent': psutil.disk_usage('/').percent
                }
                
                time.sleep(5)
                
            except Exception as e:
                logging.error(f"Resource monitoring error: {e}")
                time.sleep(5)

    def get_metrics(self):
        return self.metrics.copy()

    def stop(self):
        self.running = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=5)


def main():
    parser = argparse.ArgumentParser(description='DCIS Virtual IoT Node')
    parser.add_argument('--id', help='Node ID')
    parser.add_argument('--broker', default='192.168.0.221', help='MQTT broker address')
    parser.add_argument('--port', type=int, default=1883, help='MQTT broker port')
    parser.add_argument('--pi-mode', action='store_true', help='Run in Raspberry Pi mode')
    parser.add_argument('--count', type=int, default=1, help='Number of virtual nodes to create')
    args = parser.parse_args()
    
    nodes = []

    for i in range(args.count):
        if args.count > 1:
            node_id = f"{args.id or 'virtual_node'}_{i+1}"
        else:
            node_id = args.id
        
        node = DCISVirtualNode(node_id=node_id, is_pi=args.pi_mode)
        nodes.append(node)
        
        node.start(args.broker, args.port)
        
        if i < args.count - 1:
            time.sleep(2)  
    
    try:
        while True:
            time.sleep(60)
            for node in nodes:
                stats = node.get_statistics()
                print(f"\n📊 Node {stats['node_id']} Statistics:")
                print(f"  Discovered Devices: {stats['discovered_devices']}")
                print(f"  Detected Anomalies: {stats['detected_anomalies']}")
                print(f"  Learning Mode: {stats['learning_mode']}")
            
    except KeyboardInterrupt:
        print("\n\nShutting down virtual nodes...")
        for node in nodes:
            node.stop()

if __name__ == "__main__":
    main()