#include <WiFi.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <esp_system.h>
#include <esp_wifi.h>

// Configuration - Update these!
const char* ssid = "Very Fast Wifi";
const char* password = "Apartment115!";
const char* mqtt_server = "192.168.0.221";
const int mqtt_port = 1883;

// Device identification
String esp32_id = "esp32_monitor_" + String((uint32_t)ESP.getEfuseMac(), HEX);
const int LED_PIN = 2;  

// MQTT Client
WiFiClient espClient;
PubSubClient client(espClient);

// Timing constants
unsigned long lastHeartbeat = 0;
unsigned long lastMonitoring = 0;
unsigned long lastDiscovery = 0;
const unsigned long HEARTBEAT_INTERVAL = 15000;  // 15 seconds
const unsigned long MONITORING_INTERVAL = 30000; // 30 seconds
const unsigned long DISCOVERY_INTERVAL = 300000; // 5 minutes

// Monitoring structures
struct Coordinator {
  String coordinator_id;
  String ip;
  unsigned long last_seen;
  bool threat_detection_active;
  int threat_count;
};

struct VirtualNode {
  String node_id;
  String ip;
  unsigned long last_seen;
  bool monitoring_active;
  int anomaly_count;
};

struct Threat {
  String threat_id;
  String attack_type;
  String target;
  String severity;
  unsigned long timestamp;
};

// Tracking arrays
const int MAX_COORDINATORS = 5;
const int MAX_NODES = 10;
const int MAX_THREATS = 20;

Coordinator coordinators[MAX_COORDINATORS];
VirtualNode virtual_nodes[MAX_NODES];
Threat recent_threats[MAX_THREATS];

int coordinator_count = 0;
int virtual_node_count = 0;
int threat_count = 0;

// Performance metrics
unsigned long uptime_start = 0;
int messages_received = 0;
int messages_sent = 0;
int validations_performed = 0;
int attacks_detected = 0;

// Memory monitoring
unsigned long last_free_heap = 0;
float avg_free_heap = 0;
int heap_samples = 0;

void setup() {
  Serial.begin(115200);
  delay(100);
  
  Serial.println("\n================================================");
  Serial.println("DCIS ESP32 Cross-Monitoring Device");
  Serial.println("================================================");
  Serial.print("Device ID: ");
  Serial.println(esp32_id);
  
  // Initialize LED
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);
  
  // Initialize WiFi
  setup_wifi();
  
  // Configure MQTT
  client.setServer(mqtt_server, mqtt_port);
  client.setCallback(mqtt_callback);
  client.setBufferSize(2048);  
  
  // Connect to MQTT
  connect_mqtt();
  
  // Record start time
  uptime_start = millis();
  
  // Initial LED blink sequence
  for(int i = 0; i < 3; i++) {
    digitalWrite(LED_PIN, HIGH);
    delay(100);
    digitalWrite(LED_PIN, LOW);
    delay(100);
  }
  
  Serial.println("✓ Setup complete - Starting monitoring");
}

void setup_wifi() {
  delay(10);
  Serial.print("Connecting to WiFi: ");
  Serial.println(ssid);
  
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  
  int attempts = 0;
  while (WiFi.status() != WL_CONNECTED && attempts < 30) {
    delay(500);
    Serial.print(".");
    digitalWrite(LED_PIN, !digitalRead(LED_PIN));  
    attempts++;
  }
  
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("\n✗ WiFi connection failed - Restarting");
    ESP.restart();
  }
  
  digitalWrite(LED_PIN, LOW);
  Serial.println("\n✓ WiFi connected");
  Serial.print("  IP address: ");
  Serial.println(WiFi.localIP());
  Serial.print("  RSSI: ");
  Serial.print(WiFi.RSSI());
  Serial.println(" dBm");
}

void connect_mqtt() {
  while (!client.connected()) {
    Serial.print("Connecting to MQTT broker...");
    
    String clientId = "dcis_" + esp32_id;
    
    if (client.connect(clientId.c_str())) {
      Serial.println(" ✓ Connected");
      
      // Subscribe to topics
      subscribe_to_topics();
      
      // Announce presence
      publish_discovery();
      
      // Success indication
      digitalWrite(LED_PIN, HIGH);
      delay(500);
      digitalWrite(LED_PIN, LOW);
      
    } else {
      Serial.print(" ✗ Failed, rc=");
      Serial.print(client.state());
      Serial.println(" Retrying in 5 seconds...");
      
      // Error indication
      for(int i = 0; i < 5; i++) {
        digitalWrite(LED_PIN, HIGH);
        delay(100);
        digitalWrite(LED_PIN, LOW);
        delay(100);
      }
      
      delay(5000);
    }
  }
}

void subscribe_to_topics() {
  // Subscribe to coordinator topics
  client.subscribe("dcis/coordinators/+/heartbeat");
  client.subscribe("dcis/coordinators/+/threat");
  
  // Subscribe to node topics
  client.subscribe("dcis/nodes/+/heartbeat");
  client.subscribe("dcis/nodes/+/alert");
  
  // Subscribe to attack topics
  client.subscribe("dcis/attacks/real_time");
  client.subscribe("dcis/threats/+");
  
  // Subscribe to validation requests
  String validation_topic = "dcis/esp32/" + esp32_id + "/validate_request";
  client.subscribe(validation_topic.c_str());
  
  Serial.println("✓ Subscribed to monitoring topics");
}

void mqtt_callback(char* topic, byte* payload, unsigned int length) {
  messages_received++;
  
  // Parse JSON payload
  DynamicJsonDocument doc(1024);
  DeserializationError error = deserializeJson(doc, payload, length);
  
  if (error) {
    Serial.print("JSON parsing failed: ");
    Serial.println(error.c_str());
    return;
  }
  
  String topicStr = String(topic);
  
  // Route messages based on topic
  if (topicStr.indexOf("/coordinators/") > -1 && topicStr.endsWith("/heartbeat")) {
    handleCoordinatorHeartbeat(doc);
  }
  else if (topicStr.indexOf("/coordinators/") > -1 && topicStr.endsWith("/threat")) {
    handleCoordinatorThreat(doc);
  }
  else if (topicStr.indexOf("/nodes/") > -1 && topicStr.endsWith("/heartbeat")) {
    handleNodeHeartbeat(doc);
  }
  else if (topicStr.indexOf("/nodes/") > -1 && topicStr.endsWith("/alert")) {
    handleNodeAlert(doc);
  }
  else if (topicStr.indexOf("/attacks/") > -1 || topicStr.indexOf("/threats/") > -1) {
    handleAttackReport(doc);
  }
  else if (topicStr.endsWith("/validate_request")) {
    handleValidationRequest(doc);
  }
}

void handleCoordinatorHeartbeat(DynamicJsonDocument& doc) {
  String coord_id = doc["coordinator_id"];
  String ip = doc["ip"];
  int confirmed_threats = doc["confirmed_threats"];
  
  // Update or add coordinator
  bool found = false;
  for (int i = 0; i < coordinator_count; i++) {
    if (coordinators[i].coordinator_id == coord_id) {
      coordinators[i].ip = ip;
      coordinators[i].last_seen = millis();
      coordinators[i].threat_count = confirmed_threats;
      found = true;
      break;
    }
  }
  
  if (!found && coordinator_count < MAX_COORDINATORS) {
    coordinators[coordinator_count].coordinator_id = coord_id;
    coordinators[coordinator_count].ip = ip;
    coordinators[coordinator_count].last_seen = millis();
    coordinators[coordinator_count].threat_count = confirmed_threats;
    coordinator_count++;
    
    Serial.print("New coordinator discovered: ");
    Serial.println(coord_id);
  }
}

void handleNodeHeartbeat(DynamicJsonDocument& doc) {
  String node_id = doc["node_id"];
  String ip = doc["ip"];
  bool learning_mode = doc["learning_mode"];
  
  // Update or add node
  bool found = false;
  for (int i = 0; i < virtual_node_count; i++) {
    if (virtual_nodes[i].node_id == node_id) {
      virtual_nodes[i].ip = ip;
      virtual_nodes[i].last_seen = millis();
      virtual_nodes[i].monitoring_active = !learning_mode;
      found = true;
      break;
    }
  }
  
  if (!found && virtual_node_count < MAX_NODES) {
    virtual_nodes[virtual_node_count].node_id = node_id;
    virtual_nodes[virtual_node_count].ip = ip;
    virtual_nodes[virtual_node_count].last_seen = millis();
    virtual_nodes[virtual_node_count].monitoring_active = !learning_mode;
    virtual_node_count++;
    
    Serial.print("New node discovered: ");
    Serial.println(node_id);
  }
}

void handleCoordinatorThreat(DynamicJsonDocument& doc) {
  handleAttackReport(doc);
}

void handleNodeAlert(DynamicJsonDocument& doc) {
  String node_id = doc["node_id"];
  String threat_type = doc["threat_type"];
  
  // Update node anomaly count
  for (int i = 0; i < virtual_node_count; i++) {
    if (virtual_nodes[i].node_id == node_id) {
      virtual_nodes[i].anomaly_count++;
      break;
    }
  }
  
  Serial.print("⚠ Alert from ");
  Serial.print(node_id);
  Serial.print(": ");
  Serial.println(threat_type);
  
  // Visual indication
  digitalWrite(LED_PIN, HIGH);
  delay(100);
  digitalWrite(LED_PIN, LOW);
}

void handleAttackReport(DynamicJsonDocument& doc) {
  String threat_id = doc["threat_id"];
  String attack_type = doc["threat_type"] | doc["attack_type"];
  String target = doc["target"];
  String severity = doc["severity"];
  
  attacks_detected++;
  
  // Store threat
  if (threat_count < MAX_THREATS) {
    recent_threats[threat_count].threat_id = threat_id;
    recent_threats[threat_count].attack_type = attack_type;
    recent_threats[threat_count].target = target;
    recent_threats[threat_count].severity = severity;
    recent_threats[threat_count].timestamp = millis();
    threat_count++;
  } else {
    // Shift array and add new threat
    for (int i = 0; i < MAX_THREATS - 1; i++) {
      recent_threats[i] = recent_threats[i + 1];
    }
    recent_threats[MAX_THREATS - 1].threat_id = threat_id;
    recent_threats[MAX_THREATS - 1].attack_type = attack_type;
    recent_threats[MAX_THREATS - 1].target = target;
    recent_threats[MAX_THREATS - 1].severity = severity;
    recent_threats[MAX_THREATS - 1].timestamp = millis();
  }
  
  Serial.print("🎯 Attack detected: ");
  Serial.print(attack_type);
  Serial.print(" -> ");
  Serial.print(target);
  Serial.print(" (");
  Serial.print(severity);
  Serial.println(")");
  
  // Visual indication based on severity
  int blinks = 1;
  if (severity == "critical") blinks = 5;
  else if (severity == "high") blinks = 3;
  else if (severity == "medium") blinks = 2;
  
  for (int i = 0; i < blinks; i++) {
    digitalWrite(LED_PIN, HIGH);
    delay(50);
    digitalWrite(LED_PIN, LOW);
    delay(50);
  }
  
  // Publish cross-validation
  publishCrossValidation(attack_type, target);
}

void handleValidationRequest(DynamicJsonDocument& doc) {
  String validation_id = doc["validation_id"];
  JsonObject threat_data = doc["threat_data"];
  String coordinator = doc["coordinator"];
  
  validations_performed++;
  
  // Perform validation
  bool is_valid = validateThreat(threat_data);
  
  // Send response
  DynamicJsonDocument response(256);
  response["validation_id"] = validation_id;
  response["esp32_id"] = esp32_id;
  response["confirmed"] = is_valid;
  response["confidence"] = is_valid ? 0.85 : 0.15;
  response["timestamp"] = millis() / 1000;
  
  String response_topic = "dcis/coordinators/" + coordinator + "/validate_response";
  String response_str;
  serializeJson(response, response_str);
  
  client.publish(response_topic.c_str(), response_str.c_str());
  messages_sent++;
  
  Serial.print("✓ Validation response sent: ");
  Serial.println(is_valid ? "CONFIRMED" : "REJECTED");
}

bool validateThreat(JsonObject threat_data) {
  String attack_type = threat_data["attack_type"];
  String target = threat_data["target"];
  String severity = threat_data["severity"];
  float confidence = threat_data["confidence"];
  
  // Validation logic
  // Check if we've seen this attack recently
  for (int i = 0; i < threat_count; i++) {
    if (recent_threats[i].attack_type == attack_type && 
        recent_threats[i].target == target) {
      return true;  // We've seen this attack
    }
  }
  
  // Validate based on severity and confidence
  if (severity == "critical" && confidence > 0.6) return true;
  if (severity == "high" && confidence > 0.7) return true;
  if (confidence > 0.8) return true;
  
  // Check if target is known
  for (int i = 0; i < coordinator_count; i++) {
    if (coordinators[i].ip == target) return true;
  }
  for (int i = 0; i < virtual_node_count; i++) {
    if (virtual_nodes[i].ip == target) return true;
  }
  
  return false;
}

void publishCrossValidation(String attack_type, String target) {
  DynamicJsonDocument doc(256);
  doc["esp32_id"] = esp32_id;
  doc["validation_type"] = "cross_check";
  doc["attack_type"] = attack_type;
  doc["target"] = target;
  doc["timestamp"] = millis() / 1000;
  
  String message;
  serializeJson(doc, message);
  
  client.publish("dcis/esp32/cross_validation", message.c_str());
  messages_sent++;
}

void publish_discovery() {
  DynamicJsonDocument doc(512);
  doc["esp32_id"] = esp32_id;
  doc["ip"] = WiFi.localIP().toString();
  doc["mac"] = WiFi.macAddress();
  doc["device_type"] = "esp32_monitor";
  doc["capabilities"]["cross_monitoring"] = true;
  doc["capabilities"]["threat_validation"] = true;
  doc["capabilities"]["network_analysis"] = true;
  doc["firmware_version"] = "1.0.0";
  doc["timestamp"] = millis() / 1000;
  
  String message;
  serializeJson(doc, message);
  
  String topic = "dcis/esp32/" + esp32_id + "/discovery";
  client.publish(topic.c_str(), message.c_str());
  messages_sent++;
  
  Serial.println("✓ Discovery message published");
}

void publishESP32Status() {
  // Update heap statistics
  unsigned long current_heap = ESP.getFreeHeap();
  avg_free_heap = ((avg_free_heap * heap_samples) + current_heap) / (heap_samples + 1);
  heap_samples++;
  last_free_heap = current_heap;
  
  DynamicJsonDocument doc(512);
  doc["esp32_id"] = esp32_id;
  doc["ip"] = WiFi.localIP().toString();
  doc["uptime"] = (millis() - uptime_start) / 1000;
  doc["memory_free"] = current_heap;
  doc["memory_avg"] = (int)avg_free_heap;
  doc["wifi_rssi"] = WiFi.RSSI();
  doc["coordinators_seen"] = coordinator_count;
  doc["nodes_seen"] = virtual_node_count;
  doc["threats_observed"] = threat_count;
  doc["attacks_detected"] = attacks_detected;
  doc["validations_performed"] = validations_performed;
  doc["messages_received"] = messages_received;
  doc["messages_sent"] = messages_sent;
  doc["timestamp"] = millis() / 1000;
  
  String message;
  serializeJson(doc, message);
  
  String topic = "dcis/esp32/" + esp32_id + "/status";
  client.publish(topic.c_str(), message.c_str());
  messages_sent++;
  
  Serial.print("📊 Status published - Free heap: ");
  Serial.print(current_heap);
  Serial.print(" bytes, RSSI: ");
  Serial.print(WiFi.RSSI());
  Serial.println(" dBm");
}

void publishMonitoringData() {
  DynamicJsonDocument doc(512);
  doc["esp32_id"] = esp32_id;
  
  // Add coordinator status
  JsonArray coords = doc.createNestedArray("coordinators");
  for (int i = 0; i < coordinator_count; i++) {
    if (millis() - coordinators[i].last_seen < 60000) {  // Active in last minute
      JsonObject coord = coords.createNestedObject();
      coord["id"] = coordinators[i].coordinator_id;
      coord["active"] = true;
      coord["threats"] = coordinators[i].threat_count;
    }
  }
  
  // Add node status
  JsonArray nodes = doc.createNestedArray("nodes");
  for (int i = 0; i < virtual_node_count; i++) {
    if (millis() - virtual_nodes[i].last_seen < 60000) {  // Active in last minute
      JsonObject node = nodes.createNestedObject();
      node["id"] = virtual_nodes[i].node_id;
      node["active"] = virtual_nodes[i].monitoring_active;
      node["anomalies"] = virtual_nodes[i].anomaly_count;
    }
  }
  
  // Add recent threats summary
  doc["recent_threats"] = min(threat_count, 5);  // Last 5 threats
  doc["timestamp"] = millis() / 1000;
  
  String message;
  serializeJson(doc, message);
  
  String topic = "dcis/esp32/" + esp32_id + "/monitoring";
  client.publish(topic.c_str(), message.c_str());
  messages_sent++;
}

void performNetworkScan() {
  // Simple network connectivity check
  Serial.println("🔍 Performing network scan...");
  
  // Check gateway connectivity
  IPAddress gateway = WiFi.gatewayIP();
  
  DynamicJsonDocument doc(256);
  doc["esp32_id"] = esp32_id;
  doc["scan_type"] = "network_check";
  doc["gateway"] = gateway.toString();
  doc["subnet"] = WiFi.subnetMask().toString();
  doc["dns"] = WiFi.dnsIP().toString();
  doc["channel"] = WiFi.channel();
  doc["timestamp"] = millis() / 1000;
  
  String message;
  serializeJson(doc, message);
  
  client.publish("dcis/esp32/network_scan", message.c_str());
  messages_sent++;
}

void checkComponentHealth() {
  // Check for stale components
  unsigned long current_time = millis();
  
  // Check coordinators
  for (int i = 0; i < coordinator_count; i++) {
    if (current_time - coordinators[i].last_seen > 60000) {  // Not seen for 1 minute
      Serial.print("⚠ Coordinator ");
      Serial.print(coordinators[i].coordinator_id);
      Serial.println(" appears offline");
      
      // Report potential issue
      DynamicJsonDocument doc(256);
      doc["esp32_id"] = esp32_id;
      doc["alert_type"] = "component_offline";
      doc["component"] = coordinators[i].coordinator_id;
      doc["last_seen"] = (current_time - coordinators[i].last_seen) / 1000;
      doc["timestamp"] = millis() / 1000;
      
      String message;
      serializeJson(doc, message);
      
      client.publish("dcis/esp32/health_alert", message.c_str());
      messages_sent++;
    }
  }
  
  // Check nodes
  for (int i = 0; i < virtual_node_count; i++) {
    if (current_time - virtual_nodes[i].last_seen > 60000) {  // Not seen for 1 minute
      Serial.print("⚠ Node ");
      Serial.print(virtual_nodes[i].node_id);
      Serial.println(" appears offline");
    }
  }
}

void loop() {
  // Maintain MQTT connection
  if (!client.connected()) {
    connect_mqtt();
  }
  client.loop();
  
  unsigned long current_millis = millis();
  
  // Publish heartbeat/status
  if (current_millis - lastHeartbeat > HEARTBEAT_INTERVAL) {
    publishESP32Status();
    lastHeartbeat = current_millis;
  }
  
  // Publish monitoring data
  if (current_millis - lastMonitoring > MONITORING_INTERVAL) {
    publishMonitoringData();
    checkComponentHealth();
    lastMonitoring = current_millis;
  }
  
  // Perform network discovery
  if (current_millis - lastDiscovery > DISCOVERY_INTERVAL) {
    performNetworkScan();
    lastDiscovery = current_millis;
  }
  
  // Check WiFi connection
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("✗ WiFi disconnected - Reconnecting...");
    setup_wifi();
  }
  
  // Memory monitoring
  if (ESP.getFreeHeap() < 10000) {
    Serial.println("⚠ Low memory warning!");
    // Clear old threats if needed
    if (threat_count > 10) {
      threat_count = 10;  // Keep only recent 10
    }
  }
  
  // Heartbeat LED (subtle blink every 5 seconds)
  if (current_millis % 5000 < 50) {
    digitalWrite(LED_PIN, HIGH);
  } else {
    digitalWrite(LED_PIN, LOW);
  }
  
  delay(10);  // Small delay for stability
}