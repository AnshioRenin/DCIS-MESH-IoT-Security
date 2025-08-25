#!/usr/bin/env python3
import paho.mqtt.client as mqtt
import json
import time
import threading
import random
import socket
import psutil
import platform
import logging
from collections import defaultdict, deque
from datetime import datetime

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class RealTimeAttackSimulator:
    def __init__(self, broker_host="192.168.0.221", broker_port=1883):
        self.broker_host = broker_host
        self.broker_port = broker_port
        self.client_id = f"attack_simulator_{random.randint(1000, 9999)}"
 
        self.attack_types = {
           
            'network_reconnaissance': {
                'severity': 'medium',
                'target_types': ['all'],
                'duration': (10, 30),
                'detection_method': 'Port scan pattern detection'
            },
            'port_scan_stealth': {
                'severity': 'medium',
                'target_types': ['all'],
                'duration': (300, 600),
                'detection_method': 'Temporal correlation'
            },
            'arp_spoofing': {
                'severity': 'high',
                'target_types': ['iot', 'esp32'],
                'duration': (1, 2),
                'detection_method': 'ARP table inconsistency'
            },
            'dhcp_starvation': {
                'severity': 'critical',
                'target_types': ['network'],
                'duration': (30, 60),
                'detection_method': 'DHCP request patterns'
            },
            'dns_poisoning': {
                'severity': 'high',
                'target_types': ['all'],
                'duration': (5, 10),
                'detection_method': 'DNS response validation'
            },
            'icmp_flood': {
                'severity': 'medium',
                'target_types': ['all'],
                'duration': (10, 20),
                'detection_method': 'ICMP rate monitoring'
            },
            'syn_flood': {
                'severity': 'high',
                'target_types': ['all'],
                'duration': (5, 15),
                'detection_method': 'Half-open connections'
            },
            'udp_amplification': {
                'severity': 'high',
                'target_types': ['all'],
                'duration': (10, 30),
                'detection_method': 'Asymmetric traffic flow'
            },
       
            'mqtt_broker_flood': {
                'severity': 'high',
                'target_types': ['mesh', 'iot'],
                'duration': (5, 10),
                'detection_method': 'MQTT message rate anomaly'
            },
            'mqtt_topic_hijack': {
                'severity': 'medium',
                'target_types': ['iot', 'esp32'],
                'duration': (2, 5),
                'detection_method': 'Unauthorized subscription'
            },
            'mqtt_auth_bypass': {
                'severity': 'critical',
                'target_types': ['mesh', 'iot'],
                'duration': (10, 20),
                'detection_method': 'Failed auth monitoring'
            },
            'coap_amplification': {
                'severity': 'high',
                'target_types': ['iot'],
                'duration': (5, 15),
                'detection_method': 'CoAP response size'
            },
            'http_slowloris': {
                'severity': 'medium',
                'target_types': ['all'],
                'duration': (60, 300),
                'detection_method': 'Incomplete HTTP requests'
            },
            'websocket_hijack': {
                'severity': 'high',
                'target_types': ['all'],
                'duration': (2, 5),
                'detection_method': 'WebSocket handshake'
            },
            'tls_downgrade': {
                'severity': 'high',
                'target_types': ['all'],
                'duration': (3, 7),
                'detection_method': 'TLS negotiation'
            },
 
            'firmware_overflow': {
                'severity': 'critical',
                'target_types': ['iot', 'esp32'],
                'duration': (10, 30),
                'detection_method': 'Firmware update size'
            },
            'command_injection': {
                'severity': 'critical',
                'target_types': ['iot', 'esp32'],
                'duration': (2, 5),
                'detection_method': 'Command patterns'
            },
            'default_credentials': {
                'severity': 'high',
                'target_types': ['iot'],
                'duration': (5, 10),
                'detection_method': 'Known credential usage'
            },
            'telnet_backdoor': {
                'severity': 'critical',
                'target_types': ['iot'],
                'duration': (2, 5),
                'detection_method': 'Unexpected telnet'
            },
            'replay_attack': {
                'severity': 'medium',
                'target_types': ['iot'],
                'duration': (5, 10),
                'detection_method': 'Duplicate commands'
            },
            'session_hijack': {
                'severity': 'high',
                'target_types': ['iot'],
                'duration': (3, 7),
                'detection_method': 'Session anomaly'
            },
            'config_tampering': {
                'severity': 'high',
                'target_types': ['iot', 'esp32'],
                'duration': (5, 15),
                'detection_method': 'Config changes'
            },
            'ota_hijack': {
                'severity': 'critical',
                'target_types': ['esp32'],
                'duration': (20, 40),
                'detection_method': 'OTA signature'
            },
            'power_analysis': {
                'severity': 'medium',
                'target_types': ['esp32'],
                'duration': (60, 120),
                'detection_method': 'Power anomaly'
            },
    
            'credential_stuffing': {
                'severity': 'high',
                'target_types': ['all'],
                'duration': (30, 60),
                'detection_method': 'Multiple login attempts'
            },
            'pivot_attack': {
                'severity': 'critical',
                'target_types': ['all'],
                'duration': (60, 120),
                'detection_method': 'Connection patterns'
            },
            'privilege_escalation': {
                'severity': 'critical',
                'target_types': ['all'],
                'duration': (10, 30),
                'detection_method': 'Permission changes'
            },
            'network_traversal': {
                'severity': 'high',
                'target_types': ['all'],
                'duration': (120, 300),
                'detection_method': 'Cross-segment traffic'
            },
   
            'tcp_rst_flood': {
                'severity': 'high',
                'target_types': ['all'],
                'duration': (5, 10),
                'detection_method': 'RST packet rate'
            },
            'bandwidth_exhaustion': {
                'severity': 'critical',
                'target_types': ['all'],
                'duration': (30, 60),
                'detection_method': 'Traffic volume'
            },
            'resource_exhaustion': {
                'severity': 'critical',
                'target_types': ['esp32', 'iot'],
                'duration': (60, 120),
                'detection_method': 'Resource usage'
            },
            'connection_exhaustion': {
                'severity': 'high',
                'target_types': ['all'],
                'duration': (20, 40),
                'detection_method': 'Connection count'
            },
            'application_dos': {
                'severity': 'high',
                'target_types': ['all'],
                'duration': (30, 60),
                'detection_method': 'App response'
            },
    
            'unknown_protocol': {
                'severity': 'critical',
                'target_types': ['all'],
                'duration': (10, 30),
                'detection_method': 'Protocol anomaly'
            },
            'polymorphic_malware': {
                'severity': 'critical',
                'target_types': ['all'],
                'duration': (60, 180),
                'detection_method': 'Behavioral analysis'
            },
            'ai_generated_exploit': {
                'severity': 'critical',
                'target_types': ['all'],
                'duration': (30, 90),
                'detection_method': 'ML anomaly detection'
            },
            'supply_chain_compromise': {
                'severity': 'critical',
                'target_types': ['iot', 'esp32'],
                'duration': (120, 300),
                'detection_method': 'Component integrity'
            },
            'hardware_backdoor': {
                'severity': 'critical',
                'target_types': ['esp32'],
                'duration': (60, 120),
                'detection_method': 'Hardware behavior'
            },
            'quantum_attack_sim': {
                'severity': 'critical',
                'target_types': ['all'],
                'duration': (10, 20),
                'detection_method': 'Crypto strength'
            }
        }
     
        self.discovered_targets = {}
        self.attack_history = deque(maxlen=1000)
        self.active_attacks = {}
        self.success_rates = defaultdict(lambda: 0.5)
        self.defense_encounters = defaultdict(list)
   
        self.learning_rate = 0.1
        self.exploration_rate = 0.1
  
        self.total_attacks = 0
        self.successful_attacks = 0
        self.detected_attacks = 0
  
        self.mqtt_client = mqtt.Client(client_id=self.client_id)
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_message = self.on_message
        
        self.running = False
        self.attack_thread = None

    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logging.info(f"Attack Simulator connected to MQTT broker")
            # Subscribe to discovery topics
            client.subscribe("dcis/nodes/+/discovery")
            client.subscribe("dcis/coordinators/+/status")
            client.subscribe("dcis/esp32/+/status")
            client.subscribe("dcis/defense/+")
        else:
            logging.error(f"Failed to connect: {rc}")

    def on_message(self, client, userdata, msg):
        try:
            topic = msg.topic
            data = json.loads(msg.payload.decode())

            if "discovery" in topic or "status" in topic:
                self.process_discovery(topic, data)
            elif "defense" in topic:
                self.process_defense_response(data)
                
        except Exception as e:
            logging.error(f"Message processing error: {e}")

    def process_discovery(self, topic, data):       
        device_id = data.get('node_id') or data.get('coordinator_id') or data.get('esp32_id')
        if not device_id:
            return
            
        device_type = 'unknown'
        if 'coordinator' in topic:
            device_type = 'coordinator'
        elif 'node' in topic:
            device_type = 'iot'
        elif 'esp32' in topic:
            device_type = 'esp32'
        
        device_ip = data.get('ip', f"192.168.0.{random.randint(100, 200)}")
            
        self.discovered_targets[device_id] = {
            'id': device_id,
            'type': device_type,
            'ip': device_ip,
            'last_seen': time.time(),
            'open_ports': data.get('open_ports', []),
            'vulnerabilities': []
        }
        
        logging.info(f"Discovered target: {device_id} ({device_type}) at {device_ip}")

    def process_defense_response(self, data):        
        attack_id = data.get('attack_id')
        defense_type = data.get('action')
        
        if attack_id in self.active_attacks:
            attack = self.active_attacks[attack_id]
            attack_type = attack['attack_type']
            
           
            self.defense_encounters[attack_type].append(defense_type)
            self.update_success_rate(attack_type, False)
            
            logging.info(f"Defense {defense_type} detected for {attack_type}")

    def select_attack(self, target):        
        valid_attacks = []
        target_type = target.get('type', 'unknown')
        
        for attack_name, attack_info in self.attack_types.items():
            if 'all' in attack_info['target_types'] or target_type in attack_info['target_types']:
                valid_attacks.append(attack_name)
        
        if not valid_attacks:
            return None
  
        if random.random() < self.exploration_rate:
            
            return random.choice(valid_attacks)
        else:
            
            weights = {}
            for attack in valid_attacks:
                base_weight = self.success_rates[attack]
                defense_penalty = len(self.defense_encounters[attack]) * 0.1
                weights[attack] = max(0.1, base_weight - defense_penalty)
         
            total = sum(weights.values())
            if total == 0:
                return random.choice(valid_attacks)
                
            rand = random.uniform(0, total)
            cumsum = 0
            for attack, weight in weights.items():
                cumsum += weight
                if rand <= cumsum:
                    return attack
            
            return valid_attacks[-1]

    def execute_attack(self, target, attack_type):        
        attack_id = f"{attack_type}_{target['id']}_{int(time.time())}"
        attack_info = self.attack_types[attack_type]
        duration = random.uniform(*attack_info['duration'])
        attack_start_time = time.time()
       
        attack_record = {
            'attack_id': attack_id,
            'attack_type': attack_type,
            'target': target['id'],
            'target_ip': target.get('ip', 'unknown'),
            'severity': attack_info['severity'],
            'start_time': time.time(),
            'expected_duration': duration,
            'status': 'executing',
            'detection_method': attack_info['detection_method']
        }
        
        self.active_attacks[attack_id] = attack_record
        self.total_attacks += 1
  
        attack_notification = {
            'threat_id': attack_id,
            'source': self.get_local_ip(),
            'target': target.get('ip', 'unknown'),
            'target_ip': target.get('ip', 'unknown'),
            'threat_type': attack_type,
            'attack_type': attack_type,
            'severity': attack_info['severity'],
            'confidence': 0.95,
            'timestamp': time.time(),
            'attack_start_time': attack_start_time,  
            'method': 'attack_simulator',
            'details': {
                'attack_type': attack_type,
                'target_id': target['id'],
                'target_ip': target.get('ip', 'unknown'),
                'expected_duration': duration
            }
        }
  
        self.mqtt_client.publish(
            "dcis/attacks/real_time",
            json.dumps(attack_notification),
            qos=2
        )
        
        self.mqtt_client.publish(
            f"dcis/threats/{self.client_id}",
            json.dumps(attack_notification),
            qos=2
        )
        
        logging.info(f"🔥 ATTACK #{self.total_attacks} EXECUTED:")
        logging.info(f"   Type: {attack_type}")
        logging.info(f"   Target IP: {target.get('ip', 'unknown')}")
        logging.info(f"   Target ID: {target['id']}")
        logging.info(f"   Severity: {attack_info['severity']}")
        logging.info(f"   Duration: {duration:.1f}s")
    
        threading.Thread(target=self.simulate_attack_execution, 
                        args=(attack_id, duration)).start()
        
        return attack_record

    def simulate_attack_execution(self, attack_id, duration):        
        start_time = time.time()
        
        while time.time() - start_time < duration:
            if attack_id not in self.active_attacks:
                break  
     
            progress = (time.time() - start_time) / duration
         
            if random.random() < 0.1:  
                update = {
                    'attack_id': attack_id,
                    'progress': progress,
                    'status': 'active',
                    'timestamp': time.time()
                }
                self.mqtt_client.publish(
                    "dcis/attacks/simulation",
                    json.dumps(update)
                )            
            time.sleep(0.5)
        
        
        if attack_id in self.active_attacks:
            attack = self.active_attacks[attack_id]
            attack['status'] = 'completed'
            attack['end_time'] = time.time()
         
            success = random.random() > 0.3  
            attack['success'] = success
            
            if success:
                self.successful_attacks += 1
     
            self.update_success_rate(attack['attack_type'], success)                
            self.attack_history.append(attack)  
            del self.active_attacks[attack_id]
            
            logging.info(f"✓ Attack {attack_id} completed - Success: {success}")

    def update_success_rate(self, attack_type, success):        
        old_rate = self.success_rates[attack_type]
        new_value = 1.0 if success else 0.0
        self.success_rates[attack_type] = (1 - self.learning_rate) * old_rate + self.learning_rate * new_value

    def attack_loop(self):       
        initial_wait = random.randint(30, 60)  
        logging.info(f"⏱️ Waiting {initial_wait} seconds before first attack...")
     
        elapsed = 0
        while elapsed < initial_wait and self.running:
            time.sleep(5)
            elapsed += 5
        
        if not self.running:
            return
        
        while self.running:
            try:
               
                active_targets = [
                    target for target in self.discovered_targets.values()
                    if (time.time() - target['last_seen'] < 300 and 
                        not target.get('ip', '').startswith('127.') and
                        'simulator' not in target['id'].lower())
                ]
                
                if active_targets:
                    
                    target = random.choice(active_targets)
                    
                   
                    attack_type = self.select_attack(target)
                    
                    if attack_type:
                      
                        self.execute_attack(target, attack_type)             
                       
                        wait_minutes = random.uniform(0.5, 1.0)
                        wait_seconds = int(wait_minutes * 60)
                        
                        current_time = datetime.now()
                        next_attack_time = current_time.timestamp() + wait_seconds
                        
                        logging.info(f"⏰ NEXT ATTACK IN {wait_minutes:.1f} MINUTES ({wait_seconds} seconds)")
                        logging.info(f"   Current time: {current_time.strftime('%H:%M:%S')}")
                        logging.info(f"   Next attack at: {datetime.fromtimestamp(next_attack_time).strftime('%H:%M:%S')}")
                
                        elapsed = 0
                        while elapsed < wait_seconds and self.running:
                            time.sleep(30)  
                            elapsed += 30
                            
                            if elapsed % 60 == 0 and elapsed < wait_seconds:  
                                remaining_minutes = (wait_seconds - elapsed) / 60
                                logging.info(f"   ⏳ {remaining_minutes:.1f} minutes until next attack...")
                    else:
                        logging.info("⚠️ No valid attack type found for target")
                        time.sleep(60)  
                else:
                    logging.info("⏳ No valid targets discovered yet, waiting...")
                    time.sleep(60)  
                    
            except Exception as e:
                logging.error(f"Attack loop error: {e}")
                time.sleep(30)

    def get_local_ip(self):        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def get_statistics(self):        
        return {
            'total_attacks': self.total_attacks,
            'successful_attacks': self.successful_attacks,
            'success_rate': self.successful_attacks / max(1, self.total_attacks),
            'active_attacks': len(self.active_attacks),
            'discovered_targets': len(self.discovered_targets),
            'attack_types_used': len([k for k, v in self.success_rates.items() if v > 0]),
            'average_success_rate': sum(self.success_rates.values()) / max(1, len(self.success_rates))
        }

    def start(self):        
        self.running = True
      
        try:
            self.mqtt_client.connect(self.broker_host, self.broker_port, 60)
            self.mqtt_client.loop_start()
           
            self.attack_thread = threading.Thread(target=self.attack_loop)
            self.attack_thread.start()
            
            logging.info("🚀 Attack Simulator started - 40+ attack types loaded")
            logging.info("⏰ Attacks will occur every  60 seconds")
       
            status = {
                'simulator_id': self.client_id,
                'status': 'active',
                'attack_types': len(self.attack_types),
                'attack_interval': '60 seconds',
                'timestamp': time.time()
            }
            self.mqtt_client.publish("dcis/attacks/status", json.dumps(status))
            
        except Exception as e:
            logging.error(f"Failed to start: {e}")
            self.running = False

    def stop(self):        
        logging.info("🛑 Stopping attack simulator...")
        self.running = False
        
        if self.attack_thread:
            self.attack_thread.join(timeout=10)
 
        stats = self.get_statistics()
        stats['timestamp'] = time.time()
        stats['status'] = 'stopped'
        
        self.mqtt_client.publish("dcis/attacks/statistics", json.dumps(stats))
        
        self.mqtt_client.loop_stop()
        self.mqtt_client.disconnect()
        
        logging.info(f"Attack Simulator stopped - Total attacks: {self.total_attacks}")

def main():
    import argparse
    parser = argparse.ArgumentParser(description='DCIS Real-Time Attack Simulator')
    parser.add_argument('--broker', default='192.168.0.221', help='MQTT broker address')
    parser.add_argument('--port', type=int, default=1883, help='MQTT broker port')
    args = parser.parse_args()
    
    simulator = RealTimeAttackSimulator(args.broker, args.port)
    
    try:
        simulator.start()
 
        while True:
            time.sleep(60)
            
            stats = simulator.get_statistics()
            print(f"\n📊 Attack Statistics:")
            print(f"  Total Attacks: {stats['total_attacks']}")
            print(f"  Success Rate: {stats['success_rate']:.1%}")
            print(f"  Active Attacks: {stats['active_attacks']}")
            print(f"  Targets: {stats['discovered_targets']}")
            
    except KeyboardInterrupt:
        print("\n\nShutting down attack simulator...")
        simulator.stop()

if __name__ == "__main__":
    main()