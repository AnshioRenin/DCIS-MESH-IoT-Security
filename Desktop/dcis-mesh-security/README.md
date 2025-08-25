# DCIS Mesh: Enhancing IoT Security Through Distributed Collaborative Intelligence

## System Overview

This repository contains the complete implementation of the Distributed Collaborative Intelligent Systems (DCIS) mesh architecture with integrated real-time attack simulation for comprehensive IoT security monitoring, as developed for the MSc Cybersecurity thesis at Dublin Business School.

## Key Features
- **45 Attack Types**: Comprehensive attack simulation including network reconnaissance, protocol-specific attacks, IoT exploitation, lateral movement, DoS/DDoS, and firmware attacks
- **Byzantine Fault-Tolerant Consensus**: 67% agreement threshold for threat validation across distributed nodes
- **Real-Time Detection**: Average 1.2-second response time (range: 0.095-1.4 seconds)
- **Resource Efficient**: Operates on ESP32 with only 82KB RAM usage
- **Cost-Effective**: Complete implementation for €165 vs €4,500+ commercial solutions
- **Scalable Detection**: 88% accuracy with minimal configuration (2 coordinators) to 100% with optimal configuration (5+ coordinators)

## Research Achievement

**Detection Performance:**
- Minimal Configuration (2 coordinators): 88% detection rate, 12% false positives
- Optimal Configuration (5+ coordinators): 100% detection rate, 0% false positives
- Response Time: 1.2 seconds average across all configurations
- Resource Usage: 77% reduction in CPU utilization vs centralized systems
- Memory Efficiency: 92% reduction per node vs centralized approaches

## System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Windows PC    │    │ Raspberry Pi    │    │     ESP32       │
│ 192.168.0.171   │    │ 192.168.0.221   │    │ 192.168.0.xxx   │
│                 │    │                 │    │                 │
│ • Dashboard     │◄──►│ • MQTT Broker   │◄──►│ • Cross-Monitor │
│ • Main Coord    │    │ • Edge Coord    │    │ • Device Alerts │
│ • Attack Engine │    │ • Virtual Nodes │    │ • Web Interface │
│ • Analysis      │    │ • Local Scan    │    │ • Independence  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         ▲                      ▲                      ▲
         └──────────────────────┴──────────────────────┘
                        MQTT Communication
```

### Three-Tier Hierarchy

1. **Intelligence Hub Tier (Windows PC)**
   - Attack simulation engine with 45+ attack types
   - Real-time monitoring dashboard
   - Advanced threat analysis and correlation
   - Historical data storage and machine learning

2. **Edge Coordination Tier (Raspberry Pi)**
   - MQTT broker for mesh communication
   - Virtual node simulation for scalability testing
   - Local mesh coordination and consensus validation
   - Byzantine fault-tolerant processing

3. **Sensor Node Tier (ESP32)**
   - Cross-monitoring of peer devices
   - Lightweight anomaly detection
   - Independent threat verification
   - Resource-constrained security processing

## Prerequisites

### Hardware Requirements
- **Windows PC**: Windows 10/11, Python 3.11+, 8GB RAM minimum
- **Raspberry Pi**: Pi 4 (2GB+ RAM), Raspberry Pi OS 64-bit
- **ESP32**: ESP32 DevKit or similar microcontroller
- **Network**: WiFi router, all devices on same network segment

### Software Requirements
- Python 3.11+ with virtual environment support
- Arduino IDE 2.0+ (for ESP32 firmware)
- MQTT Broker (Mosquitto)
- Git for repository management

## Installation

### Step 1: Raspberry Pi Setup (MQTT Broker & Edge Coordinator)

```bash
# SSH into Raspberry Pi
ssh pi@192.168.0.221

# Update system packages
sudo apt update && sudo apt upgrade -y

# Install Mosquitto MQTT Broker
sudo apt install -y mosquitto mosquitto-clients python3-pip

# Configure Mosquitto for mesh communication
sudo nano /etc/mosquitto/conf.d/dcis.conf
```

Add the following configuration:
```
listener 1883 0.0.0.0
allow_anonymous true
persistence true
persistence_location /var/lib/mosquitto/
log_dest file /var/log/mosquitto/mosquitto.log
max_connections 100
```

```bash
# Restart and enable Mosquitto
sudo systemctl restart mosquitto
sudo systemctl enable mosquitto

# Verify MQTT broker is running
sudo systemctl status mosquitto

# Install Python dependencies for edge coordinator
pip3 install paho-mqtt psutil netifaces numpy
```

### Step 2: Windows Setup (Intelligence Hub)

```bash
# Clone the repository
git clone https://github.com/yourusername/dcis-mesh-security.git
cd dcis-mesh-security

# Create and activate virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/Mac

# Install required packages
pip install -r requirements.txt
```

Create `requirements.txt`:
```
paho-mqtt==1.6.1
psutil==5.9.5
netifaces==0.11.0
customtkinter==5.2.0
numpy==1.24.3
matplotlib==3.7.1
pandas==2.0.2
```

### Step 3: ESP32 Setup (Cross-Monitoring Devices)

1. **Configure Arduino IDE for ESP32:**
   - Install ESP32 board support via Board Manager
   - Add board manager URL: `https://raw.githubusercontent.com/espressif/arduino-esp32/gh-pages/package_esp32_index.json`

2. **Update ESP32 Configuration:**
   ```cpp
   // In dcis_esp32_monitor.ino
   const char* ssid = "Your_WiFi_SSID";
   const char* password = "Your_WiFi_Password";
   const char* mqtt_server = "192.168.0.221";  // Raspberry Pi IP
   ```

3. **Upload firmware to ESP32 devices**

## Running the DCIS System

### Launch Sequence (Critical Order)

1. **Start MQTT Broker** (Raspberry Pi):
```bash
# Verify broker is running
sudo systemctl status mosquitto
```

2. **Start Edge Coordinator** (Raspberry Pi):
```bash
cd dcis-mesh-security
python3 coordinator.py --id pi_coordinator --broker 192.168.0.221 --mode edge
```

3. **Launch Virtual Nodes** (Raspberry Pi):
```bash
# Start multiple virtual nodes for scalability testing
python3 virtual_node.py --broker 192.168.0.221 --count 5 --mode virtual
```

4. **Start Main Coordinator** (Windows):
```bash
# Activate virtual environment
venv\Scripts\activate

# Launch main coordinator with attack simulation
python coordinator.py --id main_coordinator --broker 192.168.0.221 --mode intelligence
```

5. **Start Attack Simulation Engine** (Windows):
```bash
# Launch comprehensive attack generator
python attack_simulator.py --broker 192.168.0.221 --attacks 45 --mode continuous
```

6. **Launch Monitoring Dashboard** (Windows):
```bash
# Start real-time monitoring interface
python dashboard.py --broker 192.168.0.221 --ui advanced
```

7. **Power ESP32 Devices** - Auto-connect and begin cross-monitoring

## System Performance Validation

### Detection Accuracy Results
| Configuration | Coordinators | Detection Rate | False Positives | Response Time |
|---------------|--------------|----------------|----------------|---------------|
| Minimal | 2 | 88% | 12% | 1.2s avg |
| Optimal | 5+ | 100% | 0% | 1.0s avg |

### Attack Coverage Testing
- **Network Reconnaissance**: 98 tests, 100% detection (optimal config)
- **Protocol Attacks**: 71 tests, 100% detection (optimal config)
- **IoT Exploitation**: 45 tests, 100% detection (optimal config)
- **DoS/DDoS**: 89 tests, 100% detection (optimal config)
- **Lateral Movement**: 73 tests, 100% detection (optimal config)

### Resource Efficiency
- **CPU Usage**: 8.9% average (77% reduction vs centralized)
- **Memory per Node**: 2.05GB distributed (92% reduction vs centralized)
- **Network Bandwidth**: 2.3 Mbps (73% reduction vs centralized)
- **ESP32 Memory**: 82KB RAM usage

## Expected System Output

### Coordinator Output (Edge/Intelligence)
```
2024-12-XX XX:XX:XX - INFO - DCIS Coordinator main_coordinator connected
2024-12-XX XX:XX:XX - INFO - 🚀 Byzantine consensus initialized (67% threshold)
2024-12-XX XX:XX:XX - INFO - Attack simulation engine loaded: 45 attack types
2024-12-XX XX:XX:XX - INFO - Device discovered: ESP32-01 (cross-monitor)
2024-12-XX XX:XX:XX - INFO - 🎯 Attack detected: firmware_exploit targeting 192.168.0.150
2024-12-XX XX:XX:XX - INFO - ✓ Consensus achieved: 4/5 nodes confirmed threat (80%)
2024-12-XX XX:XX:XX - INFO - 🛡️ Defense executed: device_isolation in 1.1s
```

### ESP32 Serial Monitor Output
```
================================================
DCIS ESP32 Cross-Monitoring Device v1.0
================================================
Device ID: esp32_monitor_a1b2c3
✓ WiFi connected - IP: 192.168.0.150
✓ MQTT broker connected: 192.168.0.221
✓ Cross-monitoring active for 4 peer devices
🎯 Anomaly detected: HIGH_CONNECTION_RATE from 192.168.0.100
✓ Consensus request sent - awaiting validation
📊 Status: Free heap 245KB, Network RSSI -45dBm
```

## Academic Research Context

This implementation represents the practical component of the MSc Cybersecurity thesis:

**"DCIS Mesh: Enhancing IoT Security Through Distributed Collaborative Intelligence"**
- **Author**: Anshio Renin Micheal Antony Xavier Soosammal
- **Institution**: Dublin Business School
- **Program**: MSc in Cyber Security
- **Supervisor**: Tejas Bhat
- **Date**: August 2025

### Research Contributions
1. **Architectural Innovation**: First implementation combining distributed collaborative intelligence with integrated attack simulation
2. **Byzantine Fault Tolerance**: Lightweight consensus protocol requiring only 2KB RAM
3. **Practical Deployment**: Complete solution for €165 total hardware cost
4. **Network Density Discovery**: Empirically validated relationship between node density and detection accuracy

## Troubleshooting

### Common Issues

**MQTT Connection Failed:**
```bash
# Check broker status
sudo systemctl status mosquitto
# Test connectivity
ping 192.168.0.221
telnet 192.168.0.221 1883
```

**ESP32 Memory Issues:**
- Reduce JSON buffer sizes in configuration
- Monitor heap with `ESP.getFreeHeap()`
- Implement garbage collection

**High False Positives:**
- Allow 5-minute learning period minimum
- Adjust detection thresholds based on environment
- Review consensus requirements (67% default)

## Performance Comparison

| Metric | DCIS Mesh | Centralized IDS | Improvement |
|--------|-----------|-----------------|-------------|
| Detection Accuracy | 88-100% | 85-90% | Up to 15% better |
| Response Time | 1.2s avg | 4-8s | 70-85% faster |
| CPU Usage | 8.9% | 38.7% | 77% reduction |
| Memory Usage | 2.05GB distributed | 24.8GB | 92% reduction |
| Total Cost (3 years) | €521 | €6,104 | 91.5% reduction |

## Future Research Directions

- **Machine Learning Integration**: Federated learning for collaborative threat intelligence
- **Protocol Optimization**: Custom MQTT extensions for security-specific communication
- **Quantum-Resistant Security**: Post-quantum cryptography implementation
- **Global Threat Intelligence**: Federated mesh networks across organizations

## License & Academic Use

This work is released under MIT License for educational and research purposes. If using this research in academic work, please cite:

```
Anshio Renin Micheal Antony Xavier Soosammal. (2025). DCIS Mesh: Enhancing IoT Security Through 
Distributed Collaborative Intelligence. MSc Thesis, Dublin Business School.
```

## Contributing

This project originated as academic research. Contributions, improvements, and extensions are welcome from the cybersecurity research community.

---

**Academic Research Project** - Dublin Business School MSc Cybersecurity Program 2024-2025