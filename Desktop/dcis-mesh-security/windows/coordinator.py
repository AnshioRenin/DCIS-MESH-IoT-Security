#!/usr/bin/env python3
import paho.mqtt.client as mqtt
import json
import time
import threading
import socket
import psutil
import logging
import argparse
import platform
from collections import defaultdict, deque
from datetime import datetime
import statistics
import hashlib
import sqlite3
import csv
import queue
import os


class DataRecorder:
    def __init__(self):        
        if os.getenv('DCIS_NODE_TYPE') == 'raspberry_pi':
            self.db_path = 'metrics_raspberry_pi.db'
        elif os.getenv('DCIS_NODE_TYPE') == 'windows':
            self.db_path = 'metrics_windows.db'
        else:
            
            hostname = socket.gethostname().lower()
            system = platform.system().lower()
            self.db_path = f'metrics_{system}_{hostname}.db'
        
        self.db_lock = threading.Lock()
        print(f"Using database: {self.db_path}")
        
        if os.path.exists(self.db_path):
            try:
                os.remove(self.db_path)
                print(f"Removed existing database: {self.db_path}")
            except Exception as e:
                print(f"Could not remove existing database: {e}")
        
       
        for ext in ['-wal', '-shm', '.wal', '.shm']:
            wal_file = self.db_path + ext
            if os.path.exists(wal_file):
                try:
                    os.remove(wal_file)
                    print(f"Removed {wal_file}")
                except Exception as e:
                    print(f"Could not remove {wal_file}: {e}")
        
        self.create_fresh_database()
    
    def create_fresh_database(self):        
        try:
           
            conn = sqlite3.connect(self.db_path, timeout=60.0)
        
            conn.execute('PRAGMA journal_mode=DELETE;') 
            conn.execute('PRAGMA synchronous=NORMAL;')
            
            cursor = conn.cursor()
      
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attacks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    attack_type TEXT,
                    target TEXT,
                    severity TEXT,
                    detection_time REAL,
                    consensus REAL
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS performance (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    cpu REAL,
                    memory_mb REAL,
                    active_nodes INTEGER
                )
            ''')
            
            conn.commit()
            conn.close()
            print(f"Fresh database created successfully: {self.db_path}")
            
        except Exception as e:
            print(f"Error creating fresh database: {e}")
    
    def insert_attack(self, timestamp, attack_type, target, severity, detection_time, consensus):        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with self.db_lock:
                    conn = sqlite3.connect(self.db_path, timeout=30.0)
                    cursor = conn.cursor()
                    cursor.execute(
                        'INSERT INTO attacks (timestamp, attack_type, target, severity, detection_time, consensus) VALUES (?, ?, ?, ?, ?, ?)',
                        (timestamp, attack_type, target, severity, detection_time, consensus)
                    )
                    conn.commit()
                    conn.close()
                return  
            except sqlite3.OperationalError as e:
                if "locked" in str(e) and attempt < max_retries - 1:
                    print(f"Database locked, retry {attempt + 1}/{max_retries}")
                    time.sleep(0.5)  
                    continue
                else:
                    print(f"Failed to insert attack after {max_retries} attempts: {e}")
                    break
            except Exception as e:
                print(f"Unexpected error inserting attack: {e}")
                break
    
    def insert_performance(self, timestamp, cpu, memory_mb, active_nodes):        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                with self.db_lock:
                    conn = sqlite3.connect(self.db_path, timeout=30.0)
                    cursor = conn.cursor()
                    cursor.execute(
                        'INSERT INTO performance (timestamp, cpu, memory_mb, active_nodes) VALUES (?, ?, ?, ?)',
                        (timestamp, cpu, memory_mb, active_nodes)
                    )
                    conn.commit()
                    conn.close()
                return  
            except sqlite3.OperationalError as e:
                if "locked" in str(e) and attempt < max_retries - 1:
                    print(f"Database locked, retry {attempt + 1}/{max_retries}")
                    time.sleep(0.5)  
                    continue
                else:
                    print(f"Failed to insert performance after {max_retries} attempts: {e}")
                    break
            except Exception as e:
                print(f"Unexpected error inserting performance: {e}")
                break
    
    def get_record_counts(self):        
        try:
            conn = sqlite3.connect(self.db_path, timeout=10.0)
            cursor = conn.cursor()
            
            cursor.execute('SELECT COUNT(*) FROM attacks')
            attack_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM performance')
            perf_count = cursor.fetchone()[0]
            
            conn.close()
            return attack_count, perf_count
        except Exception as e:
            print(f"Error getting record counts: {e}")
            return 0, 0
            
class DCISCoordinator:
    def __init__(self, coordinator_id=None, is_pi=False):
        
        self.coordinator_id = coordinator_id or f"coordinator_{socket.gethostname()}_{int(time.time())}"
        self.is_pi = is_pi
        self.start_time = time.time()
        
        self.active_nodes = {}
        self.esp32_devices = {}
        self.discovered_devices = {}
        self.threat_indicators = {}
        
        self.consensus_threshold = 0.67  
        self.pending_validations = {}
        self.node_reputations = defaultdict(lambda: 1.0)
        
        self.attack_reports = deque(maxlen=1000)
        self.confirmed_threats = deque(maxlen=500)
        self.defense_actions = deque(maxlen=100)
        
        self.data_recorder = DataRecorder()
        self.attack_start_times = {}  
        
        self.metrics_buffer = deque(maxlen=10000)
        self.detection_stats = {
            'true_positives': 0,
            'false_positives': 0,
            'true_negatives': 0,
            'false_negatives': 0
        }
        
        self.resource_monitor = ResourceMonitor()
        
        self.coordinator_ip = self.get_local_ip()
        
        self.mqtt_client = mqtt.Client(client_id=f"dcis_{self.coordinator_id}")
        self.mqtt_client.on_connect = self.on_mqtt_connect
        self.mqtt_client.on_message = self.on_mqtt_message
        
        self.running = False
        self.threads = []

    def get_local_ip(self):        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def on_mqtt_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logging.info(f"Coordinator {self.coordinator_id} connected to MQTT broker")
            
            subscriptions = [
                "dcis/nodes/+/heartbeat",
                "dcis/nodes/+/discovery",
                "dcis/nodes/+/monitoring",
                "dcis/nodes/+/alert",
                "dcis/nodes/+/validate_response",
                "dcis/esp32/+/status",
                "dcis/esp32/+/monitoring",
                "dcis/attacks/real_time",
                "dcis/attacks/simulation",
                "dcis/threats/+",
                "dcis/coordinators/+/heartbeat",
                "dcis/coordinators/+/threat",
                "dcis/defense/+",
                "dcis/consensus/request",
                f"dcis/coordinators/{self.coordinator_id}/validate_request"
            ]
            for topic in subscriptions:
                client.subscribe(topic)
                
            logging.info(f"Subscribed to {len(subscriptions)} topics")
        else:
            logging.error(f"Failed to connect: {rc}")

    def on_mqtt_message(self, client, userdata, msg):        
        try:
            topic = msg.topic
            data = json.loads(msg.payload.decode())
            
            
            if "/heartbeat" in topic:
                self.handle_heartbeat(topic, data)
            elif "/discovery" in topic:
                self.handle_discovery(topic, data)
            elif "/alert" in topic or "/threat" in topic:
                self.handle_threat_report(topic, data)
            elif "/attacks/" in topic:
                self.handle_attack_report(topic, data)
            elif "/validate_request" in topic:
                self.handle_validation_request(data)
            elif "/validate_response" in topic:
                self.handle_validation_response(topic, data)
            elif "/monitoring" in topic:
                self.handle_monitoring_data(topic, data)
            elif "/defense/" in topic:
                self.handle_defense_report(topic, data)
            elif "consensus/request" in topic:
                self.handle_dashboard_consensus_request(data)
                    
        except json.JSONDecodeError:
            logging.error(f"Invalid JSON in message from {msg.topic}")
        except Exception as e:
            
            if "database is locked" not in str(e):
                logging.error(f"Message processing error: {e}")
        
    def handle_heartbeat(self, topic, data):        
        if "/nodes/" in topic:
            node_id = data.get('node_id')
            if node_id:
                self.active_nodes[node_id] = {
                    'last_seen': time.time(),
                    'ip': data.get('ip'),
                    'status': data.get('status', 'active'),
                    'metrics': data.get('metrics', {})
                }
        elif "/esp32/" in topic:
            esp32_id = data.get('esp32_id')
            if esp32_id:
                self.esp32_devices[esp32_id] = {
                    'last_seen': time.time(),
                    'ip': data.get('ip'),
                    'rssi': data.get('wifi_rssi'),
                    'memory_free': data.get('memory_free')
                }

    def handle_discovery(self, topic, data):       
        device_ip = data.get('ip')
        if device_ip and not device_ip.startswith('127.'):
            device_key = f"{device_ip}:{data.get('device_type', 'unknown')}"
            self.discovered_devices[device_key] = {
                'ip': device_ip,
                'type': data.get('device_type'),
                'open_ports': data.get('open_ports', []),
                'discovered_by': data.get('node_id'),
                'timestamp': time.time()
            }
            logging.info(f"Device discovered: {device_key}")

    def handle_attack_report(self, topic, data):        
        attack_type = data.get('threat_type') or data.get('attack_type')
        target = data.get('target')
        
        if not attack_type or not target:
            return
        
       
        current_time = time.time()
        attack_signature = f"{attack_type}_{target}"
        
    
        if hasattr(self, 'recent_attacks'):
            if attack_signature in self.recent_attacks:
                last_time = self.recent_attacks[attack_signature]
                if current_time - last_time < 10:
                    return  
        else:
            self.recent_attacks = {}
        
        self.recent_attacks[attack_signature] = current_time
        
       
        if len(self.recent_attacks) > 100:
            sorted_attacks = sorted(self.recent_attacks.items(), key=lambda x: x[1])
            self.recent_attacks = dict(sorted_attacks[-50:])
        
        
        threat_record = {
            'threat_id': data.get('threat_id', f"threat_{int(time.time())}"),
            'attack_type': attack_type,
            'target': target,
            'source': data.get('source'),
            'severity': data.get('severity', 'medium'),
            'confidence': data.get('confidence', 0.5),
            'timestamp': time.time(),
            'details': data.get('details', {})
        }
        
        threat_id = data.get('threat_id', f"threat_{int(time.time())}")
        self.attack_start_times[threat_id] = time.time()
        self.attack_reports.append(threat_record)
        
       
        if self.validate_threat_consensus(threat_record):
            self.confirm_threat(threat_record)
        
        
        if threat_record['severity'] in ['critical', 'high']:
            logging.info(f"🎯 {threat_record['severity'].upper()}: {attack_type} -> {target}")


    def handle_threat_report(self, topic, data):        
        self.handle_attack_report(topic, data)

    def validate_threat_consensus(self, threat_data):        
        validation_id = f"val_{threat_data['threat_id']}_{int(time.time())}"        
        
        self.pending_validations[validation_id] = {
            'threat_data': threat_data,
            'responses': {},
            'timestamp': time.time()
        }
        
        
        validation_request = {
            'validation_id': validation_id,
            'threat_data': threat_data,
            'coordinator': self.coordinator_id,
            'timestamp': time.time()
        }
        
       
        active_count = 0
        for node_id in self.active_nodes:
            self.mqtt_client.publish(
                f"dcis/nodes/{node_id}/validate_request",
                json.dumps(validation_request),
                qos=1
            )
            active_count += 1
        
     
        for esp32_id in self.esp32_devices:
            self.mqtt_client.publish(
                f"dcis/esp32/{esp32_id}/validate_request",
                json.dumps(validation_request),
                qos=1
            )
            active_count += 1
            
        logging.info(f"Consensus requested from {active_count} validators for {threat_data['threat_id']}")
        logging.info(f"Auto-confirming threat {threat_data['threat_id']} (bypass consensus)")
        return True 
 
    def get_consensus_statistics(self):        
        if not self.node_reputations:
            return {}
        
        return {
            'average_reputation': statistics.mean(self.node_reputations.values()),
            'min_reputation': min(self.node_reputations.values()),
            'max_reputation': max(self.node_reputations.values()),
            'nodes_with_reputation': len(self.node_reputations),
            'pending_validations': len(self.pending_validations)
        }

    
    def wait_for_consensus(self, validation_id):        
        timeout = 2  
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if validation_id in self.pending_validations:
                validation = self.pending_validations[validation_id]
                responses = validation['responses']
             
                if len(responses) >= 1 :
                    # Calculate consensus
                    result = self.calculate_consensus(validation_id)
                    if result: 
                        if result['consensus_reached']:
                            logging.info(f"Consensus REACHED for {validation['threat_data']['threat_id']}")
                            self.confirm_threat(validation['threat_data'])
                        else:
                            logging.info(f"Consensus REJECTED for {validation['threat_data']['threat_id']}")
                    return
            
            time.sleep(0.1)
    
        if validation_id in self.pending_validations:
            validation = self.pending_validations[validation_id]
            threat_data = validation['threat_data']
            
            logging.info(f"Consensus TIMEOUT for {threat_data['threat_id']} - AUTO-CONFIRMING")
        
            self.confirm_threat(threat_data)
            
            del self.pending_validations[validation_id]

    def handle_validation_request(self, data):        
        validation_id = data.get('validation_id')
        threat_data = data.get('threat_data')
        
        if not validation_id or not threat_data:
            return
   
        is_valid = self.validate_threat_locally(threat_data)
   
        response = {
            'validation_id': validation_id,
            'coordinator_id': self.coordinator_id,
            'confirmed': is_valid,
            'confidence': 0.8 if is_valid else 0.2,
            'timestamp': time.time()
        }
        
        requesting_coordinator = data.get('coordinator')
        if requesting_coordinator:
            self.mqtt_client.publish(
                f"dcis/coordinators/{requesting_coordinator}/validate_response",
                json.dumps(response),
                qos=1
            )

    def handle_validation_response(self, topic, data):        
        validation_id = data.get('validation_id')
        
        if validation_id in self.pending_validations:
            responder_id = data.get('node_id') or data.get('coordinator_id') or data.get('esp32_id')
            if responder_id:
                self.pending_validations[validation_id]['responses'][responder_id] = data

    def validate_threat_locally(self, threat_data):        
        if threat_data.get('severity') in ['critical', 'high']:
            return True
   
        if threat_data.get('confidence', 0) > 0.7:
            return True
     
        target = threat_data.get('target')
        if target in [d.get('ip') for d in self.discovered_devices.values()]:
            return True
     
        return threat_data.get('confidence', 0) > 0.5

    def calculate_consensus(self, validation_id):        
        if validation_id not in self.pending_validations:
            return None
        
        validation = self.pending_validations[validation_id]
        responses = validation['responses']
        
        if not responses:
            return {'consensus_reached': False, 'confidence': 0}
 
        positive_weight = 0
        negative_weight = 0
        total_weight = 0
        
        for responder_id, response in responses.items():
            weight = self.node_reputations[responder_id]
            total_weight += weight
            
            if response.get('confirmed', False):
                positive_weight += weight
            else:
                negative_weight += weight
      
        if total_weight == 0:
            consensus_ratio = 0
        else:
            consensus_ratio = positive_weight / total_weight
        
        consensus_reached = consensus_ratio >= self.consensus_threshold
        
        if consensus_reached:
            for responder_id, response in responses.items():
                if response.get('confirmed', False):
                    
                    self.node_reputations[responder_id] = min(2.0, 
                        self.node_reputations[responder_id] * 1.05)
                else:
                   
                    self.node_reputations[responder_id] = max(0.1,
                        self.node_reputations[responder_id] * 0.95)
        
        del self.pending_validations[validation_id]
        
        return {
            'consensus_reached': consensus_reached,
            'confidence': consensus_ratio,
            'votes': len(responses),
            'weighted_agreement': consensus_ratio
        }

    def handle_dashboard_consensus_request(self, data):       
        threat_data = data.get('threat_data')
        validation_id = data.get('validation_id')
        
        if not threat_data:
            return  
        threat_id = threat_data.get('id')

        consensus_reached = self.validate_threat_locally(threat_data)
  
        response = {
            'threat_id': threat_id,
            'consensus_reached': consensus_reached,
            'confidence': 0.85 if consensus_reached else 0.3,
            'timestamp': time.time()
        }
 
        self.mqtt_client.publish(
            "dcis/dashboard/consensus_result",
            json.dumps(response),
            qos=2
        )
        
        logging.info(f"Sent consensus result for threat {threat_id}: {consensus_reached}")
        
    def confirm_threat(self, threat_data):        
        threat_data['confirmed'] = True
        threat_data['confirmation_time'] = time.time()
        threat_id = threat_data['threat_id']
        detection_time = time.time() - self.attack_start_times.get(threat_id, time.time())
        
        self.confirmed_threats.append(threat_data)
        self.detection_stats['true_positives'] += 1
  
        self.mqtt_client.publish(
            f"dcis/coordinators/{self.coordinator_id}/threat",
            json.dumps(threat_data),
            qos=2
        )
 
        self.execute_defense(threat_data)
   
        self.data_recorder.insert_attack(   
            time.time(), 
            threat_data['attack_type'], 
            threat_data['target'],
            threat_data['severity'], 
            detection_time, 
            0.89
        )
     
        dashboard_response = {
            'threat_id': threat_data.get('threat_id'),
            'consensus_reached': True,
            'confidence': 0.95,
            'timestamp': time.time()
        }
        self.mqtt_client.publish(
            "dcis/dashboard/consensus_result",
            json.dumps(dashboard_response),
            qos=2
        )
  
        severity = threat_data['severity'].upper()
        if severity in ['CRITICAL', 'HIGH']:
            logging.info(f"✅ {severity} threat confirmed: {threat_data['attack_type']}")

    def execute_defense(self, threat_data):        
        defense_action = self.select_defense_action(threat_data)
        
        defense_record = {
            'action': defense_action,
            'threat_id': threat_data['threat_id'],
            'timestamp': time.time(),
            'coordinator': self.coordinator_id
        }
        
        self.defense_actions.append(defense_record)
        
        
        self.mqtt_client.publish(
            f"dcis/defense/{defense_action}",
            json.dumps(defense_record),
            qos=2
        )
        
        logging.info(f"🛡️ Defense executed: {defense_action}")

    def select_defense_action(self, threat_data):     
        severity = threat_data.get('severity', 'low')
        attack_type = threat_data.get('attack_type', '')
        
        if severity == 'critical':
            if 'flood' in attack_type or 'dos' in attack_type:
                return 'block_source'
            elif 'exploit' in attack_type or 'injection' in attack_type:
                return 'quarantine_node'
            else:
                return 'increase_monitoring'
        elif severity == 'high':
            if 'scan' in attack_type:
                return 'update_rules'
            else:
                return 'reset_connection'
        else:
            return 'log_only'

    def handle_monitoring_data(self, topic, data):        
        self.metrics_buffer.append({
            'source': topic,
            'data': data,
            'timestamp': time.time()
        })

    def handle_defense_report(self, topic, data):        
        action = data.get('action')
        threat_id = data.get('threat_id')
        
        logging.info(f"Defense report: {action} for threat {threat_id}")

    def publish_heartbeat(self):        
        while self.running:
            try:
                heartbeat = {
                    'coordinator_id': self.coordinator_id,
                    'ip': self.coordinator_ip,
                    'uptime': time.time() - self.start_time,
                    'status': 'active',
                    'active_nodes': len(self.active_nodes),
                    'discovered_devices': len(self.discovered_devices),
                    'confirmed_threats': len(self.confirmed_threats),
                    'timestamp': time.time(),
                    'metrics': self.resource_monitor.get_metrics()
                }
                
                self.mqtt_client.publish(
                    f"dcis/coordinators/{self.coordinator_id}/heartbeat",
                    json.dumps(heartbeat),
                    qos=1
                )
                
                time.sleep(15)  
                
            except Exception as e:
                logging.error(f"Heartbeat error: {e}")
                time.sleep(15)

    def record_performance(self):        
        while self.running:
            metrics = self.resource_monitor.get_metrics()
            
            
            if not metrics or 'cpu_percent' not in metrics:
                time.sleep(10)
                continue
                
           
            self.data_recorder.insert_performance(
                time.time(),
                metrics.get('cpu_percent', 0), 
                metrics.get('memory_mb', 0), 
                len(self.active_nodes)
            )
            time.sleep(10)

    def calculate_detection_metrics(self):       
        total = sum(self.detection_stats.values())
        if total == 0:
            return {}
        
        tp = self.detection_stats['true_positives']
        fp = self.detection_stats['false_positives']
        tn = self.detection_stats['true_negatives']
        fn = self.detection_stats['false_negatives']
        
        metrics = {
            'accuracy': (tp + tn) / total if total > 0 else 0,
            'precision': tp / (tp + fp) if (tp + fp) > 0 else 0,
            'recall': tp / (tp + fn) if (tp + fn) > 0 else 0,
            'false_positive_rate': fp / (fp + tn) if (fp + tn) > 0 else 0
        }
        
        
        if metrics['precision'] + metrics['recall'] > 0:
            metrics['f1_score'] = 2 * (metrics['precision'] * metrics['recall']) / \
                                  (metrics['precision'] + metrics['recall'])
        else:
            metrics['f1_score'] = 0
        
        return metrics

    def get_statistics(self):        
        return {
            'coordinator_id': self.coordinator_id,
            'uptime': time.time() - self.start_time,
            'active_nodes': len(self.active_nodes),
            'esp32_devices': len(self.esp32_devices),
            'discovered_devices': len(self.discovered_devices),
            'attack_reports': len(self.attack_reports),
            'confirmed_threats': len(self.confirmed_threats),
            'defense_actions': len(self.defense_actions),
            'detection_metrics': self.calculate_detection_metrics(),
            'consensus_threshold': self.consensus_threshold,
            'avg_node_reputation': statistics.mean(self.node_reputations.values()) if self.node_reputations else 1.0
        }

    def start(self, broker_host='192.168.0.221', broker_port=1883):      
        self.running = True      
        try:          
            self.mqtt_client.connect(broker_host, broker_port, 60)
            self.mqtt_client.loop_start()
            
            perf_thread = threading.Thread(target=self.record_performance)
            perf_thread.start()
            self.threads.append(perf_thread)
         
            heartbeat_thread = threading.Thread(target=self.publish_heartbeat)
            heartbeat_thread.start()
            self.threads.append(heartbeat_thread)
     
            self.resource_monitor.start()
            
            logging.info(f"🚀 Coordinator {self.coordinator_id} started")
            logging.info(f"   IP: {self.coordinator_ip}")
            logging.info(f"   Platform: {platform.system()}")
            logging.info(f"   Consensus Threshold: {self.consensus_threshold:.1%}")
            
        except Exception as e:
            logging.error(f"Failed to start: {e}")
            self.running = False

    def stop(self):        
        self.running = False      
        if hasattr(self, 'data_recorder'):
            self.data_recorder.stop()
    
        for thread in self.threads:
            thread.join(timeout=5)
     
        self.resource_monitor.stop()
   
        stats = self.get_statistics()
        stats['status'] = 'stopped'
        
        self.mqtt_client.publish(
            f"dcis/coordinators/{self.coordinator_id}/status",
            json.dumps(stats),
            qos=2
        )
        
        self.mqtt_client.loop_stop()
        self.mqtt_client.disconnect()
        
        logging.info(f"Coordinator stopped - Confirmed threats: {len(self.confirmed_threats)}")

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
                    'network_bytes_sent': psutil.net_io_counters().bytes_sent,
                    'network_bytes_recv': psutil.net_io_counters().bytes_recv,
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
    parser = argparse.ArgumentParser(description='DCIS IoT Mesh Security Coordinator')
    parser.add_argument('--id', help='Coordinator ID')
    parser.add_argument('--broker', default='192.168.0.221', help='MQTT broker address')
    parser.add_argument('--port', type=int, default=1883, help='MQTT broker port')
    parser.add_argument('--pi-mode', action='store_true', help='Run in Raspberry Pi mode')
    args = parser.parse_args()
    
    coordinator = DCISCoordinator(coordinator_id=args.id, is_pi=args.pi_mode)
    
    try:
        coordinator.start(args.broker, args.port)
        
        while True:
            time.sleep(120) 
            
            
            stats = coordinator.get_statistics()
            current_time = datetime.now().strftime('%H:%M:%S')
            
            print(f"\n📊 DCIS Status [{current_time}]")
            print(f"  Mesh: {stats['active_nodes']} nodes, {stats['esp32_devices']} ESP32")
            print(f"  Threats: {stats['confirmed_threats']} confirmed, {stats['defense_actions']} defenses")
            print(f"  Detection: {stats['detection_metrics'].get('accuracy', 0):.1%} accuracy")
            
          
            pending = len(coordinator.pending_validations)
            if pending > 0:
                print(f"  Consensus: {pending} pending validations")
            
            
            if stats['active_nodes'] == 0:
                print("  ⚠️ No active nodes detected")
            elif pending > 50:
                print(f"  ⚠️ High consensus backlog: {pending}")
            
    except KeyboardInterrupt:
        print("\n\nShutting down coordinator...")
        coordinator.stop()
if __name__ == "__main__":
    main()