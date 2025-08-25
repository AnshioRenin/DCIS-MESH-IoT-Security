#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import customtkinter as ctk
import paho.mqtt.client as mqtt
import json
import time
import threading
import random
import hashlib
import smtplib
import sqlite3
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import deque, defaultdict
from datetime import datetime, timedelta
import logging
import math


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

class AuthenticationSystem:
    def __init__(self):
        self.setup_database()
        self.otp_storage = {}  
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        self.sender_email = "ansgou4@gmail.com"  
        self.sender_password = "zanf xdzi avir aqiu"     
        
    def setup_database(self):
        try:
            self.conn = sqlite3.connect('dcis_users.db')
            self.cursor = self.conn.cursor()
            
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    name TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    verified INTEGER DEFAULT 0
                )
            ''')
            self.conn.commit()
        except Exception as e:
            logging.error(f"Database setup failed: {e}")
        
    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
        
    def validate_email(self, email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
        
    def generate_otp(self):       
        return str(random.randint(100000, 999999))
        
    def send_otp_email(self, email, otp):        
        try:           
            msg = MIMEMultipart()
            msg['From'] = self.sender_email
            msg['To'] = email
            msg['Subject'] = 'DCIS Security System - OTP Verification'
            
            body = f'''
            <html>
                <body style="font-family: Arial, sans-serif;">
                    <h2 style="color: #1f6feb;">DCIS Security System</h2>
                    <p>Your One-Time Password (OTP) for login verification:</p>
                    <h1 style="color: #2ea043; font-size: 36px; letter-spacing: 5px;">{otp}</h1>
                    <p>This OTP will expire in 5 minutes.</p>
                </body>
            </html>
            '''
            
            msg.attach(MIMEText(body, 'html'))
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.sender_email, self.sender_password)
                server.send_message(msg)
           
            
            return True
            
        except Exception as e:
            logging.error(f"Failed to send OTP: {e}")
            return False
            
    def register_user(self, email, password, name):       
        try:
            password_hash = self.hash_password(password)
            self.cursor.execute(
                "INSERT INTO users (email, password_hash, name, verified) VALUES (?, ?, ?, 0)",
                (email, password_hash, name)
            )
            self.conn.commit()
            return True, "Registration successful! Please verify with OTP."
        except sqlite3.IntegrityError:
            return False, "Email already registered!"
        except Exception as e:
            return False, f"Registration failed: {e}"
            
    def verify_login(self, email, password):        
        try:
            password_hash = self.hash_password(password)
            self.cursor.execute(
                "SELECT * FROM users WHERE email = ? AND password_hash = ?",
                (email, password_hash)
            )
            user = self.cursor.fetchone()
            
            if user:
               
                self.cursor.execute(
                    "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE email = ?",
                    (email,)
                )
                self.conn.commit()
                return True, user[3] 
            return False, None
        except Exception as e:
            logging.error(f"Login verification failed: {e}")
            return False, None


class LoginWindow:  
    def __init__(self, on_success_callback):
        self.on_success = on_success_callback
        self.auth = AuthenticationSystem()
        self.current_user = None
        self.otp_email = None
        
       
        self.window = ctk.CTk()
        self.window.title("DCIS Security System - Authentication")
        self.window.geometry("500x800")
        self.window.resizable(False, False)
        
      
        self.window.update()
        x = (self.window.winfo_screenwidth() // 2) - (500 // 2)
        y = (self.window.winfo_screenheight() // 2) - (800 // 2)
        self.window.geometry(f"500x800+{x}+{y}")
        
        self.setup_ui()
        
    def setup_ui(self):        
        main_frame = ctk.CTkFrame(self.window, corner_radius=0)
        main_frame.pack(fill="both", expand=True)
        
        
        title_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        title_frame.pack(pady=(30, 15))
        
        icon_label = ctk.CTkLabel(title_frame, text="🔐", font=("Arial", 48))
        icon_label.pack()
        
        title_label = ctk.CTkLabel(
            title_frame,
            text="DCIS Mesh Security",
            font=("Arial", 26, "bold")
        )
        title_label.pack(pady=(10, 5))
        
        subtitle_label = ctk.CTkLabel(
            title_frame,
            text="DCIS - IoT Cross-Monitoring Security System",
            font=("Arial", 12),
            text_color="gray"
        )
        subtitle_label.pack()
        
        
        self.tabview = ctk.CTkTabview(main_frame, width=420, height=580)
        self.tabview.pack(pady=(10, 15))
        
        self.login_tab = self.tabview.add("🔐 Sign In")
        self.signup_tab = self.tabview.add("📝 Sign Up")
        
     
        self.setup_login_tab()
        self.setup_signup_tab()
        
        footer_label = ctk.CTkLabel(
            main_frame,
            text="Real-Time IoT Mesh Security Research",
            font=("Arial", 10),
            text_color="gray",
            justify="center"
        )
        footer_label.pack(pady=(10, 20))
        
    def setup_login_tab(self):
        login_container = ctk.CTkFrame(self.login_tab, fg_color="transparent")
        login_container.pack(fill="both", expand=True)
        
        ctk.CTkLabel(login_container, text="Sign in to access the dashboard", 
                    font=("Arial", 12, "bold")).pack(pady=(20, 15))
        
        
        ctk.CTkLabel(login_container, text="Email Address", font=("Arial", 11)).pack(pady=(0, 3))
        self.login_email = ctk.CTkEntry(
            login_container,
            width=300,
            height=38,
            placeholder_text="your.email@example.com"
        )
        self.login_email.pack(pady=3)
        
     
        ctk.CTkLabel(login_container, text="Password", font=("Arial", 11)).pack(pady=(10, 3))
        self.login_password = ctk.CTkEntry(
            login_container,
            width=300,
            height=38,
            placeholder_text="Enter your password",
            show="●"
        )
        self.login_password.pack(pady=3)
        
       
        self.login_button = ctk.CTkButton(
            login_container,
            text="🔐 SIGN IN",
            width=300,
            height=50,
            font=("Arial", 15, "bold"),
            command=self.handle_login,
            fg_color="#1f6feb",
            hover_color="#0969da",
            corner_radius=10
        )
        self.login_button.pack(pady=(20, 10))
        
      
        self.login_status = ctk.CTkLabel(
            login_container,
            text="",
            font=("Arial", 10),
            text_color="gray"
        )
        self.login_status.pack()
        
        
        self.otp_frame = ctk.CTkFrame(login_container, fg_color="transparent")
        
        ctk.CTkLabel(self.otp_frame, text="Enter 6-Digit OTP", font=("Arial", 11, "bold")).pack(pady=(10, 3))
        self.login_otp = ctk.CTkEntry(
            self.otp_frame,
            width=300,
            height=42,
            placeholder_text="000000",
            font=("Arial", 16, "bold"),
            justify="center"
        )
        self.login_otp.pack(pady=5)
        
       
        demo_button = ctk.CTkButton(
            login_container,
            text="🚀 Demo Access (Skip Auth)",
            width=300,
            height=35,
            fg_color="gray",
            command=self.demo_login
        )
        demo_button.pack(pady=(20, 10))
        
    def setup_signup_tab(self):       
        signup_container = ctk.CTkFrame(self.signup_tab, fg_color="transparent")
        signup_container.pack(fill="both", expand=True)
        
        
        ctk.CTkLabel(signup_container, text="Create your account", 
                    font=("Arial", 12, "bold")).pack(pady=(10, 15))
        
       
        ctk.CTkLabel(signup_container, text="Full Name", font=("Arial", 11)).pack(pady=(0, 2))
        self.signup_name = ctk.CTkEntry(
            signup_container,
            width=300,
            height=36,
            placeholder_text="Your Name"
        )
        self.signup_name.pack(pady=(2, 8))
        
          
        ctk.CTkLabel(signup_container, text="Email Address", font=("Arial", 11)).pack(pady=(0, 2))
        self.signup_email = ctk.CTkEntry(
            signup_container,
            width=300,
            height=36,
            placeholder_text="your.email@example.com"
        )
        self.signup_email.pack(pady=(2, 8))
        
        
        ctk.CTkLabel(signup_container, text="Password", font=("Arial", 11)).pack(pady=(0, 2))
        self.signup_password = ctk.CTkEntry(
            signup_container,
            width=300,
            height=36,
            placeholder_text="Min 6 characters",
            show="●"
        )
        self.signup_password.pack(pady=(2, 8))
        
        
        ctk.CTkLabel(signup_container, text="Confirm Password", font=("Arial", 11)).pack(pady=(0, 2))
        self.signup_confirm = ctk.CTkEntry(
            signup_container,
            width=300,
            height=36,
            placeholder_text="Re-enter password",
            show="●"
        )
        self.signup_confirm.pack(pady=(2, 8))
        
        
        self.signup_button = ctk.CTkButton(
            signup_container,
            text="🚀 CREATE ACCOUNT",
            width=300,
            height=50,
            font=("Arial", 15, "bold"),
            command=self.handle_signup,
            fg_color="#2ea043",
            hover_color="#28a745",
            corner_radius=10
        )
        self.signup_button.pack(pady=(15, 10))
        
        
        self.signup_status = ctk.CTkLabel(
            signup_container,
            text="",
            font=("Arial", 10),
            text_color="gray"
        )
        self.signup_status.pack()
        
        
        self.signup_otp_frame = ctk.CTkFrame(signup_container, fg_color="transparent")
        
        ctk.CTkLabel(self.signup_otp_frame, text="Enter 6-Digit OTP", font=("Arial", 11, "bold")).pack(pady=(10, 3))
        self.signup_otp = ctk.CTkEntry(
            self.signup_otp_frame,
            width=300,
            height=42,
            placeholder_text="000000",
            font=("Arial", 16, "bold"),
            justify="center"
        )
        self.signup_otp.pack(pady=5)
            
    def demo_login(self):       
        self.current_user = "Demo User"
        self.window.after(100, self.close_and_launch)  
        
    def close_and_launch(self):       
        self.window.quit()
        self.window.destroy()
        if self.current_user:
            self.on_success(self.current_user)
        
    def handle_login(self):       
        if self.otp_frame.winfo_viewable():
            entered_otp = self.login_otp.get().strip()
            
            if len(entered_otp) != 6 or not entered_otp.isdigit():
                messagebox.showerror("Error", "Please enter valid 6-digit OTP")
                return
            
            if self.otp_email in self.auth.otp_storage:
                stored = self.auth.otp_storage[self.otp_email]
                
                if datetime.now() > stored['expires']:
                    messagebox.showerror("Error", "OTP expired")
                    del self.auth.otp_storage[self.otp_email]
                   
                    self.otp_frame.pack_forget()
                    self.login_button.configure(text="🔐 SIGN IN")
                    self.login_status.configure(text="", text_color="gray")
                    self.login_otp.delete(0, 'end')
                    return
                    
                if entered_otp == stored['otp']:
                    self.current_user = stored['name']
                    del self.auth.otp_storage[self.otp_email]
                    self.login_status.configure(text="✅ Login successful!", text_color="#2ea043")
                    messagebox.showinfo("Success", f"✅ Welcome {self.current_user}!")
                   
                    self.window.quit()
            else:
                messagebox.showerror("Error", "OTP session not found")
        else:
           
            email = self.login_email.get().strip()
            password = self.login_password.get()
            
            if not email or not password:
                messagebox.showerror("Error", "Please enter email and password")
                return
                
            if not self.auth.validate_email(email):
                messagebox.showerror("Error", "Invalid email format")
                return
                
            success, name = self.auth.verify_login(email, password)
            
            if success:
                otp = self.auth.generate_otp()
                self.auth.otp_storage[email] = {
                    'otp': otp,
                    'expires': datetime.now() + timedelta(minutes=5),
                    'name': name
                }
                
                self.otp_email = email
                print(f"DEBUG: Generated OTP: {otp}")  
                
                if self.auth.send_otp_email(email, otp):
                    
                    self.otp_frame.pack(pady=10)
                    self.login_button.configure(text="✅ VERIFY OTP")
                    self.login_status.configure(text=f"📧 OTP sent to {email}", text_color="#1f6feb")
                    messagebox.showinfo("OTP Sent", f"OTP sent to {email}\nDemo OTP: {otp}")
            else:
                messagebox.showerror("Error", "Invalid credentials")
            
    def handle_signup(self):        
        if self.signup_otp_frame.winfo_viewable():
            entered_otp = self.signup_otp.get().strip()
            
            if len(entered_otp) != 6 or not entered_otp.isdigit():
                messagebox.showerror("Error", "Please enter valid 6-digit OTP")
                return
            
            if self.otp_email in self.auth.otp_storage:
                stored = self.auth.otp_storage[self.otp_email]
                
                if datetime.now() > stored['expires']:
                    messagebox.showerror("Error", "OTP expired")
                    del self.auth.otp_storage[self.otp_email]
                    
                    self.signup_otp_frame.pack_forget()
                    self.signup_button.configure(text="🚀 CREATE ACCOUNT")
                    self.signup_status.configure(text="", text_color="gray")
                    self.signup_otp.delete(0, 'end')
                    return
                    
                if entered_otp == stored['otp']:
                    
                    try:
                        self.auth.cursor.execute(
                            "UPDATE users SET verified = 1 WHERE email = ?",
                            (self.otp_email,)
                        )
                        self.auth.conn.commit()
                    except:
                        pass
                    
                    self.current_user = stored['name']
                    del self.auth.otp_storage[self.otp_email]
                    self.signup_status.configure(text="✅ Account verified successfully!", text_color="#2ea043")
                    messagebox.showinfo("Success", f"✅ Account created! Welcome {self.current_user}!")
                    self.window.quit() 
                else:
                    messagebox.showerror("Error", "Invalid OTP")
            else:
                messagebox.showerror("Error", "OTP session not found")
        else:
            
            name = self.signup_name.get().strip()
            email = self.signup_email.get().strip()
            password = self.signup_password.get()
            confirm = self.signup_confirm.get()
            
            if not all([name, email, password, confirm]):
                messagebox.showerror("Error", "Please fill all fields")
                return
                
            if not self.auth.validate_email(email):
                messagebox.showerror("Error", "Invalid email format")
                return
                
            if len(password) < 6:
                messagebox.showerror("Error", "Password must be at least 6 characters")
                return
                
            if password != confirm:
                messagebox.showerror("Error", "Passwords do not match")
                return
                
            success, message = self.auth.register_user(email, password, name)
            
            if success:
                otp = self.auth.generate_otp()
                self.auth.otp_storage[email] = {
                    'otp': otp,
                    'expires': datetime.now() + timedelta(minutes=5),
                    'name': name
                }
                
                self.otp_email = email
                print(f"DEBUG: Generated OTP: {otp}")  
                
                if self.auth.send_otp_email(email, otp):
                    self.signup_otp_frame.pack(pady=10)
                    self.signup_button.configure(text="✅ VERIFY OTP")
                    self.signup_status.configure(text=f"📧 OTP sent to {email}", text_color="#2ea043")
                    messagebox.showinfo("Success", f"Account created!\n\n📧 OTP sent to: {email}\n🔢 Demo OTP: {otp}")
            else:
                messagebox.showerror("Error", message)
        
    def run(self):      
        self.window.mainloop()
        
       
        if self.current_user:
            user = self.current_user
            callback = self.on_success
            
          
            self.window.destroy()
            
            
            import tkinter as tk
            tk._default_root = None
            
           
            callback(user)
        else:
            self.window.destroy()


class EnhancedDCISMonitor:
      
    def __init__(self, root, user_name, broker_host='192.168.0.221'):
        self.root = root
        self.user_name = user_name
        self.broker_host = broker_host
        self.start_time = time.time()
        
   
        self.root.geometry("1700x950")
        self.root.title(f"DCIS Mesh Security Monitor - {user_name}")
        

        self.components = {
            'coordinators': {},
            'nodes': {},
            'esp32': {}
        }
        
        self.blocked_ips = set()  
        self.threat_signatures = {}  
        self.node_heartbeats = {}  
        self.esp32_heartbeats = {}  
        
        self.connections = defaultdict(list)
        self.live_threats = deque(maxlen=500)
        self.defense_actions = deque(maxlen=500)
        self.discovered_devices = {}
        self.device_attacks = defaultdict(list)
        self.selected_threat = None
        
        
        self.metrics = {
            'detection_rate': 0.0,
            'response_time': 0.0,
            'false_positive_rate': 0.0,
            'consensus_threshold': 67
        }
        
        
        self.setup_modern_ui()
        
        
        self.mqtt_client = mqtt.Client(client_id=f"dashboard_{int(time.time())}")
        self.mqtt_client.on_connect = self.on_mqtt_connect
        self.mqtt_client.on_message = self.on_mqtt_message
        
      
        self.connect_mqtt()
        
        self.pending_consensus = {}
        self.consensus_responses = defaultdict(list)
        self.mqtt_client.subscribe("dcis/dashboard/consensus_result")
        
        
        
        self.running = True
        
        self.defense_widgets={}
        self.setup_timer_updates()
        
    
    def setup_timer_updates(self):    
        self.running = True
        self.schedule_updates()

    def schedule_updates(self):    
        if self.running and hasattr(self, 'root'):
            try:
                self.update_metrics()
                self.update_health()
                self.update_statistics()
                self.draw_true_mesh_topology()
                self.update_device_discovery()
                self.calculate_real_metrics()
                
               
                active_threats = [t for t in self.live_threats 
                                if t['status'] == 'ACTIVE' and t['consensus'] == 'Confirmed']
                
                if active_threats and hasattr(self, 'defense_content'):                    
                    if "SYSTEM SECURE" in self.threat_status_label.cget("text"):
                        self.update_defense_center_for_threat(active_threats[0])
                        
            except Exception as e:
                logging.error(f"Update error: {e}")
            
            
            self.root.after(2000, self.schedule_updates)
            
    def setup_modern_ui(self):
        self.root.grid_rowconfigure(0, weight=0)
        self.root.grid_rowconfigure(1, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
        
        self.setup_header()
        
       
        main_frame = ctk.CTkFrame(self.root, corner_radius=0)
        main_frame.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)
        
        
        self.tabview = ctk.CTkTabview(
            main_frame,
            corner_radius=10,
            segmented_button_fg_color="#1e1e1e",
            segmented_button_selected_color="#1f6feb",
            segmented_button_unselected_color="#2b2b2b"
        )
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)
        
        
        self.dashboard_tab = self.tabview.add("📊 Dashboard")
        self.mesh_tab = self.tabview.add("🔗 Mesh Topology")
        self.threats_tab = self.tabview.add("⚠️ Threat Analysis")
        self.defense_tab = self.tabview.add("🛡️ Defense Center")
        self.devices_tab = self.tabview.add("📱 Device Discovery")
        self.statistics_tab = self.tabview.add("📈 Statistics")
        
        
        self.setup_dashboard_tab()
        self.setup_true_mesh_topology_tab()
        self.setup_interactive_threats_tab()
        self.setup_contextual_defense_tab()
        self.setup_device_discovery_tab()
        self.setup_statistics_tab()
        
    def calculate_real_metrics(self):            
        try:
            if len(self.live_threats) > 0:
               
                completed_threats = [t for t in self.live_threats if t.get('consensus') != 'Pending']
                
                if len(completed_threats) > 0:
                    detected = len([t for t in completed_threats if t.get('consensus') == 'Confirmed'])
                    total = len(completed_threats)
                    
                    self.metrics['detection_rate'] = (detected / total * 100)
                    
                    
                    response_times = [t.get('response_time', 0) for t in completed_threats 
                                    if t.get('response_time', 0) > 0]
                    if response_times:
                        self.metrics['response_time'] = sum(response_times) / len(response_times)
                    
                    
                    false_positives = len([t for t in completed_threats if t.get('consensus') == 'Rejected'])
                    self.metrics['false_positive_rate'] = (false_positives / total * 100) if total > 0 else 0
                    
                   
                    if hasattr(self, 'threat_stats_labels') and 'Detection Rate' in self.threat_stats_labels:
                        self.threat_stats_labels["Detection Rate"].configure(
                            text=f"Detection Rate\n{self.metrics['detection_rate']:.1f}%"
                        )
                        self.threat_stats_labels["Response Time"].configure(
                            text=f"Response Time\n{self.metrics['response_time']:.1f}s"
                        )
                        self.threat_stats_labels["False Positive"].configure(
                            text=f"False Positive\n{self.metrics['false_positive_rate']:.1f}%"
                        )
                        
        except Exception as e:
            logging.error(f"Error calculating metrics: {e}")
        
    def setup_header(self):
        header = ctk.CTkFrame(self.root, height=60, corner_radius=0)
        header.grid(row=0, column=0, sticky="ew", padx=0, pady=0)
        header.grid_columnconfigure(1, weight=1)
        
        # Title
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.grid(row=0, column=0, padx=20, pady=10)
        
        ctk.CTkLabel(
            title_frame,
            text="🔐 DCIS Mesh Security",
            font=("Arial", 20, "bold")
        ).pack(side="left", padx=(0, 10))
        
        ctk.CTkLabel(
            title_frame,
            text="Real-Time Cross-Monitoring",
            font=("Arial", 12),
            text_color="gray"
        ).pack(side="left")
        
       
        self.system_status = ctk.CTkLabel(
            header,
            text="🟢 System Online",
            font=("Arial", 12),
            text_color="#2ea043"
        )
        self.system_status.grid(row=0, column=1)
        
       
        user_frame = ctk.CTkFrame(header, fg_color="transparent")
        user_frame.grid(row=0, column=2, padx=20, pady=10)
        
        ctk.CTkLabel(
            user_frame,
            text=f"👤 {self.user_name}",
            font=("Arial", 12)
        ).pack(side="left", padx=10)
        
        ctk.CTkButton(
            user_frame,
            text="Logout",
            width=80,
            height=30,
            command=self.logout
        ).pack(side="left")
        
    def setup_dashboard_tab(self):        
        self.dashboard_tab.grid_columnconfigure((0, 1, 2), weight=1)
        self.dashboard_tab.grid_rowconfigure(1, weight=1)
        
        metrics_frame = ctk.CTkFrame(self.dashboard_tab, fg_color="transparent")
        metrics_frame.grid(row=0, column=0, columnspan=3, sticky="ew", padx=5, pady=5)
        
        self.metric_cards = {}
        metrics_data = [
            ("Active Nodes", "0", "#2ea043", "📡"),
            ("Coordinators", "0", "#1f6feb", "🎛️"),
            ("ESP32 Devices", "0", "#fd7e14", "📟"),
            ("Active Threats", "0", "#da3633", "⚠️"),
            ("Defense Actions", "0", "#0969da", "🛡️"),
            ("Total Devices", "0", "#8b44ac", "🔍")
        ]
        
        for i, (title, value, color, icon) in enumerate(metrics_data):
            card = self.create_metric_card(metrics_frame, title, value, color, icon)
            card.grid(row=0, column=i, padx=5, pady=5, sticky="ew")
            self.metric_cards[title] = card
        
        metrics_frame.grid_columnconfigure(tuple(range(6)), weight=1)
        
        
        left_frame = ctk.CTkFrame(self.dashboard_tab)
        left_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        
        ctk.CTkLabel(left_frame, text="📡 Live Activity", font=("Arial", 16, "bold")).pack(pady=10)
        
        self.activity_text = ctk.CTkTextbox(left_frame, font=("Consolas", 10))
        self.activity_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
       
        right_frame = ctk.CTkFrame(self.dashboard_tab)
        right_frame.grid(row=1, column=2, sticky="nsew", padx=5, pady=5)
        
        ctk.CTkLabel(right_frame, text="💚 System Health", font=("Arial", 16, "bold")).pack(pady=10)
        
        self.health_text = ctk.CTkTextbox(right_frame, font=("Consolas", 10))
        self.health_text.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
    def create_metric_card(self, parent, title, value, color, icon):       
        card = ctk.CTkFrame(parent, corner_radius=10)
        
        icon_label = ctk.CTkLabel(card, text=icon, font=("Arial", 24))
        icon_label.pack(pady=(10, 5))
        
        value_label = ctk.CTkLabel(card, text=value, font=("Arial", 28, "bold"), text_color=color)
        value_label.pack()
        
        title_label = ctk.CTkLabel(card, text=title, font=("Arial", 11), text_color="gray")
        title_label.pack(pady=(5, 10))
        
        card.value_label = value_label
        return card
        
    def setup_true_mesh_topology_tab(self):        
        header_frame = ctk.CTkFrame(self.mesh_tab)
        header_frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(
            header_frame,
            text="🔗 Every Component Monitors Every Other Component",
            font=("Arial", 16, "bold")
        ).pack(side="left", padx=10)
        
        self.mesh_info = ctk.CTkLabel(
            header_frame,
            text="Components: 0 | Connections: 0",
            font=("Arial", 12),
            text_color="#2ea043"
        )
        self.mesh_info.pack(side="right", padx=10)
        
       
        canvas_frame = ctk.CTkFrame(self.mesh_tab)
        canvas_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.mesh_canvas = tk.Canvas(canvas_frame, bg='#0f0f23', highlightthickness=0)
        self.mesh_canvas.pack(fill="both", expand=True)
        
       
        legend_frame = ctk.CTkFrame(self.mesh_tab)
        legend_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        legends = [
            ("🎛️ Windows Coord", "#1f6feb"),
            ("🖥️ Pi Coord", "#0969da"),
            ("📡 Virtual Node", "#2ea043"),
            ("📟 ESP32", "#fd7e14"),
            ("── Cross-Monitor", "#667eea"),
            ("⚡ Active Threat", "#da3633")
        ]
        
        for text, color in legends:
            frame = ctk.CTkFrame(legend_frame, fg_color="transparent")
            frame.pack(side="left", padx=15)
            ctk.CTkLabel(frame, text=text, text_color=color, font=("Arial", 11)).pack()
            
    def setup_interactive_threats_tab(self):       
        header_frame = ctk.CTkFrame(self.threats_tab)
        header_frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(
            header_frame,
            text="⚠️ Threat Analysis - Double-click for details",
            font=("Arial", 16, "bold")
        ).pack(pady=5)
        
       
        stats_frame = ctk.CTkFrame(self.threats_tab)
        stats_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.threat_stats_labels = {}
        stats = [
            ("Detection Rate", f"{self.metrics['detection_rate']}%", "#2ea043"),
            ("Response Time", f"{self.metrics['response_time']}s", "#1f6feb"),
            ("False Positive", f"{self.metrics['false_positive_rate']}%", "#fd7e14"),
            ("Consensus", f"{self.metrics['consensus_threshold']}%", "#8b44ac")
        ]
        
        for title, value, color in stats:
            frame = ctk.CTkFrame(stats_frame, fg_color="transparent")
            frame.pack(side="left", expand=True)
            label = ctk.CTkLabel(frame, text=f"{title}\n{value}", font=("Arial", 12), text_color=color)
            label.pack()
            self.threat_stats_labels[title] = label
        
       
        table_frame = ctk.CTkFrame(self.threats_tab)
        table_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Treeview', background='#2b2b2b', foreground='white', fieldbackground='#2b2b2b')
        style.configure('Treeview.Heading', background='#1f6feb', foreground='white')
        
        columns = ('Time', 'Source IP', 'Target IP', 'Attack Type', 'Severity', 'Consensus', 'Status')
        self.threat_tree = ttk.Treeview(table_frame, columns=columns, show='headings', style='Treeview')
        
        for col in columns:
            self.threat_tree.heading(col, text=col)
            self.threat_tree.column(col, width=110)
        
       
        self.threat_tree.bind('<Double-1>', self.show_threat_details)
        self.threat_tree.bind('<Button-3>', self.show_threat_context_menu)
        
        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.threat_tree.yview)
        self.threat_tree.configure(yscrollcommand=scrollbar.set)
        
        self.threat_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
    
    def setup_contextual_defense_tab(self):        
        header_frame = ctk.CTkFrame(self.defense_tab)
        header_frame.pack(fill="x", padx=10, pady=10)
        
       
        title_container = ctk.CTkFrame(header_frame, fg_color="transparent")
        title_container.pack(fill="x")
        
        ctk.CTkLabel(
            title_container,
            text="🛡️ Contextual Defense Center",
            font=("Arial", 18, "bold")
        ).pack(side="left", pady=10)
        
       
        ctk.CTkButton(
            title_container,
            text="🔄 Check Threats",
            command=self.check_and_update_defense_center,
            width=120,
            height=32,
            fg_color="#1f6feb"
        ).pack(side="right", padx=10, pady=10)
        
        
        self.threat_status_label = ctk.CTkLabel(
            header_frame,
            text="🟢 System Secure - No active threats",
            font=("Arial", 12),
            text_color="#2ea043"
        )
        self.threat_status_label.pack()
        
        
        
       
        self.defense_content = ctk.CTkFrame(self.defense_tab)
        self.defense_content.pack(fill="both", expand=True, padx=10, pady=10)
        
       
        self.show_secure_state()
        
      
        log_frame = ctk.CTkFrame(self.defense_tab)
        log_frame.pack(fill="x", padx=10, pady=(0, 10), ipady=100)
        
        ctk.CTkLabel(log_frame, text="📜 Defense Log", font=("Arial", 14, "bold")).pack(pady=10)
        
        self.defense_log = ctk.CTkTextbox(log_frame, font=("Consolas", 10), height=80)
        self.defense_log.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
    def setup_device_discovery_tab(self):       
        header_frame = ctk.CTkFrame(self.devices_tab)
        header_frame.pack(fill="x", padx=10, pady=10)
        
        ctk.CTkLabel(
            header_frame,
            text="📱 Network Device Discovery & Monitoring",
            font=("Arial", 16, "bold")
        ).pack(pady=10)
        
    
        stats_frame = ctk.CTkFrame(self.devices_tab)
        stats_frame.pack(fill="x", padx=10, pady=(0, 10))
        
        self.device_stats = {}
        device_metrics = [
            ("Coordinators", "0", "#1f6feb"),
            ("Virtual Nodes", "0", "#2ea043"),
            ("ESP32 Devices", "0", "#fd7e14"),
            ("Healthy", "0", "#28a745"),
            ("Cross-Links", "0", "#8b44ac")
        ]
        
        for title, value, color in device_metrics:
            card = ctk.CTkFrame(stats_frame)
            card.pack(side="left", expand=True, padx=5, pady=5)
            
            value_label = ctk.CTkLabel(card, text=value, font=("Arial", 20, "bold"), text_color=color)
            value_label.pack(pady=(10, 5))
            
            title_label = ctk.CTkLabel(card, text=title, font=("Arial", 10), text_color="gray")
            title_label.pack(pady=(0, 10))
            
            card.value_label = value_label
            self.device_stats[title] = card
        
        
        list_frame = ctk.CTkFrame(self.devices_tab)
        list_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        ctk.CTkLabel(list_frame, text="All Discovered Devices", font=("Arial", 14, "bold")).pack(pady=10)
        
       
        columns = ('Type', 'Device ID', 'IP Address', 'Health', 'Last Seen', 'Monitoring')
        self.device_tree = ttk.Treeview(list_frame, columns=columns, show='headings', style='Treeview')
        
        for col in columns:
            self.device_tree.heading(col, text=col)
            self.device_tree.column(col, width=120)
        
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.device_tree.yview)
        self.device_tree.configure(yscrollcommand=scrollbar.set)
        
        self.device_tree.pack(side="left", fill="both", expand=True, padx=(10, 0))
        scrollbar.pack(side="right", fill="y", padx=(0, 10))
        
    def setup_statistics_tab(self):       
        scroll_frame = ctk.CTkScrollableFrame(self.statistics_tab)
        scroll_frame.pack(fill="both", expand=True, padx=10, pady=10)
        
        ctk.CTkLabel(scroll_frame, text="📊 System Statistics", font=("Arial", 18, "bold")).pack(pady=10)
        
        self.stats_text = ctk.CTkTextbox(scroll_frame, height=600, font=("Consolas", 11))
        self.stats_text.pack(fill="both", expand=True, padx=10, pady=10)
        
    def draw_true_mesh_topology(self):        
        self.mesh_canvas.delete("all")
        
        width = self.mesh_canvas.winfo_width()
        height = self.mesh_canvas.winfo_height()
        
        if width <= 1 or height <= 1:
            return
        
        cx, cy = width // 2, height // 2
        positions = {}
        all_components = []
        
        
        for coord_id in self.components['coordinators']:
            all_components.append(('coordinator', coord_id))
        
        for node_id in self.components['nodes']:
            all_components.append(('node', node_id))
        
        for esp_id in self.components['esp32']:
            all_components.append(('esp32', esp_id))
        
        num_components = len(all_components)
        
        if num_components == 0:
            self.mesh_canvas.create_text(
                cx, cy,
                text="🔍 Scanning for mesh components...",
                fill="#667eea",
                font=("Arial", 16)
            )
            self.mesh_info.configure(text="Components: 0 | Connections: 0")
            return
        
   
        radius = min(width, height) * 0.3
        
        for i, (comp_type, comp_id) in enumerate(all_components):
            angle = (i * 2 * math.pi / num_components) - (math.pi / 2)
            x = cx + radius * math.cos(angle)
            y = cy + radius * math.sin(angle)
            positions[(comp_type, comp_id)] = (x, y)
        
        
        total_connections = 0
        for i, comp1 in enumerate(all_components):
            for j, comp2 in enumerate(all_components):
                if i < j:  
                    x1, y1 = positions[comp1]
                    x2, y2 = positions[comp2]
                    
                    self.mesh_canvas.create_line(
                        x1, y1, x2, y2,
                        fill="#667eea",
                        width=1,
                        dash=(5, 3)
                    )
                    total_connections += 1
        
     
        for (comp_type, comp_id), (x, y) in positions.items():
            comp_data = self.components[comp_type + ('s' if comp_type != 'esp32' else '')].get(comp_id, {})
            
            if comp_type == 'coordinator':
                color = "#1f6feb" if 'windows' in comp_id.lower() else "#0969da"
                self.mesh_canvas.create_oval(
                    x-30, y-30, x+30, y+30,
                    fill=color,
                    outline="white",
                    width=2
                )
                self.mesh_canvas.create_text(x, y, text="🎛️", font=("Arial", 16))
                self.mesh_canvas.create_text(x, y+40, text=comp_id[:12], fill="white", font=("Arial", 9))
                
            elif comp_type == 'node':
                self.mesh_canvas.create_oval(
                    x-25, y-25, x+25, y+25,
                    fill="#2ea043",
                    outline="white",
                    width=2
                )
                self.mesh_canvas.create_text(x, y, text="📡", font=("Arial", 14))
                self.mesh_canvas.create_text(x, y+35, text=comp_id[:12], fill="white", font=("Arial", 9))
                
            elif comp_type == 'esp32':
                self.mesh_canvas.create_rectangle(
                    x-25, y-20, x+25, y+20,
                    fill="#fd7e14",
                    outline="white",
                    width=2
                )
                self.mesh_canvas.create_text(x, y, text="📟", font=("Arial", 14))
                self.mesh_canvas.create_text(x, y+30, text=comp_id[:12], fill="white", font=("Arial", 9))
        
       
        self.mesh_info.configure(text=f"Components: {num_components} | Cross-Connections: {total_connections}")
        
     
        self.mesh_canvas.create_text(
            10, height - 30,
            text="TRUE MESH: Every component monitors ALL others",
            fill="#2ea043",
            font=("Arial", 11, "bold"),
            anchor="w"
        )
        self.mesh_canvas.create_text(
            10, height - 15,
            text=f"Total monitoring relationships: {total_connections}",
            fill="white",
            font=("Arial", 10),
            anchor="w"
        )
        
    def update_mesh_topology(self):        
        import math        
        if not hasattr(self, 'mesh_canvas'):
            return
        
        try:
            if not self.mesh_canvas.winfo_exists():
                return
                
            self.mesh_canvas.delete("all")
            width = self.mesh_canvas.winfo_width()
            height = self.mesh_canvas.winfo_height()
            
            if width <= 1 or height <= 1:
                return
            
           
            active_threats = {}
            for threat in self.live_threats:
                if threat['status'] == 'ACTIVE':
                    target = threat.get('target', '')
                    if target:
                        active_threats[target] = threat['severity']
          
            cx, cy = width // 2, height // 2
            
            
        except tk.TclError:
            pass     
    
        
    def show_threat_details(self, event):        
        selection = self.threat_tree.selection()
        if not selection:
            return
        
        item = self.threat_tree.item(selection[0])
        values = item['values']
        
        if not values:
            return
        
        
        details_window = ctk.CTkToplevel(self.root)
        details_window.title("🚨 Threat Analysis")
        details_window.geometry("600x500")
        details_window.transient(self.root)
        
       
        details_window.update_idletasks()
        x = (details_window.winfo_screenwidth() - 600) // 2
        y = (details_window.winfo_screenheight() - 500) // 2
        details_window.geometry(f"+{x}+{y}")
        
        
        main_frame = ctk.CTkFrame(details_window)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(
            main_frame,
            text="🚨 Detailed Threat Analysis",
            font=("Arial", 18, "bold"),
            text_color="#da3633"
        ).pack(pady=15)
        
        
        details_text = f"""
Threat Details:
═══════════════════════════════════════════════

⏰ Detection Time: {values[0]}
🔴 Source IP: {values[1]}
🎯 Target IP: {values[2]}
⚡ Attack Type: {values[3]}
🚨 Severity: {values[4]}
📊 Consensus: {values[5]}
📌 Status: {values[6]}

Impact Analysis:
═══════════════════════════════════════════════
{self.get_threat_impact(values[3])}

Recommended Actions:
═══════════════════════════════════════════════
{self.get_threat_recommendations(values[3])}
"""
        
        text_widget = ctk.CTkTextbox(main_frame, font=("Consolas", 11))
        text_widget.pack(fill="both", expand=True, pady=10)
        text_widget.insert("1.0", details_text)
        
        
        button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        button_frame.pack(fill="x", pady=10)
        
        ctk.CTkButton(
            button_frame,
            text="🛡️ Execute Defense",
            command=lambda: self.execute_threat_defense(values[3], details_window),
            fg_color="#28a745",
            width=150
        ).pack(side="left", padx=5)
        
        ctk.CTkButton(
            button_frame,
            text="Close",
            command=details_window.destroy,
            width=100
        ).pack(side="right", padx=5)
        
    def show_threat_context_menu(self, event):       
        selection = self.threat_tree.selection()
        if not selection:
            return
        
        menu = tk.Menu(self.root, tearoff=0, bg='#2b2b2b', fg='white')
        menu.add_command(label="🔍 View Details", command=lambda: self.show_threat_details(event))
        menu.add_command(label="🛡️ Quick Defense", command=self.quick_defend)
        menu.add_separator()
        menu.add_command(label="📋 Copy Info", command=self.copy_threat_info)
        
        menu.tk_popup(event.x_root, event.y_root)
        
    def get_threat_impact(self, attack_type):        
        impacts = {
            'mqtt_broker_flood': 'High impact on MQTT communication. May disrupt IoT device connectivity.',
            'command_injection': 'Critical! Device compromise possible. Immediate action required.',
            'arp_spoofing': 'Network traffic interception risk. Man-in-the-middle attacks possible.',
            'port_scan_stealth': 'Reconnaissance activity. Potential precursor to targeted attack.',
            'default_credentials': 'High risk of unauthorized access. Change credentials immediately.'
        }
        return impacts.get(attack_type, 'Unknown impact. Manual analysis recommended.')
        
    def get_threat_recommendations(self, attack_type):       
        recommendations = {
            'mqtt_broker_flood': '1. Implement rate limiting\n2. Block source IP\n3. Reset MQTT connections',
            'command_injection': '1. Quarantine affected device\n2. Apply input validation\n3. Update firmware',
            'arp_spoofing': '1. Enable ARP protection\n2. Use static ARP entries\n3. Segment network',
            'port_scan_stealth': '1. Block scanning IP\n2. Enable IDS/IPS\n3. Close unused ports',
            'default_credentials': '1. Force password change\n2. Implement account lockout\n3. Enable MFA'
        }
        return recommendations.get(attack_type, '1. Investigate threat\n2. Increase monitoring\n3. Alert security team')
        
    def show_secure_state(self):        
        for widget in self.defense_content.winfo_children():
            widget.destroy()
        
        secure_frame = ctk.CTkFrame(self.defense_content)
        secure_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(
            secure_frame,
            text="🟢 SYSTEM SECURE",
            font=("Arial", 24, "bold"),
            text_color="#2ea043"
        ).pack(pady=30)
        
        ctk.CTkLabel(
            secure_frame,
            text="All components actively cross-monitoring\nNo threats detected",
            font=("Arial", 12),
            justify="center"
        ).pack(pady=20)
        
        
        manual_frame = ctk.CTkFrame(secure_frame)
        manual_frame.pack(pady=30)
        
        ctk.CTkLabel(manual_frame, text="Manual Actions", font=("Arial", 14, "bold")).pack(pady=10)
        
        actions = [
            ("Increase Monitoring", self.increase_monitoring, "#1f6feb"),
            ("System Scan", self.system_scan, "#fd7e14"),
            ("Update Rules", self.update_rules, "#2ea043")
        ]
        
        for text, cmd, color in actions:
            ctk.CTkButton(
                manual_frame,
                text=text,
                command=cmd,
                width=150,
                fg_color=color
            ).pack(side="left", padx=5)
            
    def check_and_update_defense_center(self):        
        active = [t for t in self.live_threats 
                if t['status'] == 'ACTIVE' and t['consensus'] == 'Confirmed']
        if active:
            self.update_defense_center_for_threat(active[0])
            self.add_defense_log(f"{datetime.now().strftime('%H:%M:%S')} - Manual check: {len(active)} active threats found")
        else:
            self.show_secure_state()
            self.threat_status_label.configure(
                text="🟢 System Secure - No active threats",
                text_color="#2ea043"
            )
            self.add_defense_log(f"{datetime.now().strftime('%H:%M:%S')} - Manual check: System secure")
            
    def show_threat_defense(self, threat):       
        for widget in self.defense_content.winfo_children():
            widget.destroy()
        
        self.threat_status_label.configure(
            text=f"🔴 ACTIVE THREAT: {threat['type']}",
            text_color="#da3633"
        )
        
        threat_frame = ctk.CTkFrame(self.defense_content)
        threat_frame.pack(fill="both", expand=True, padx=20, pady=20)
        
        ctk.CTkLabel(
            threat_frame,
            text=f"🚨 {threat['type'].upper()} DETECTED",
            font=("Arial", 18, "bold"),
            text_color="#da3633"
        ).pack(pady=15)
        
       
        actions = self.get_contextual_actions(threat['type'])
        
        ctk.CTkLabel(
            threat_frame,
            text="Recommended Defense Actions:",
            font=("Arial", 14, "bold")
        ).pack(pady=10)
        
      
        for action in actions:
            action_frame = ctk.CTkFrame(threat_frame)
            action_frame.pack(fill="x", padx=10, pady=5)
            
            ctk.CTkLabel(
                action_frame,
                text=f"🛡️ {action['name']}",
                font=("Arial", 12, "bold")
            ).pack(side="left", padx=10)
            
            ctk.CTkLabel(
                action_frame,
                text=action['description'],
                font=("Arial", 11),
                text_color="gray"
            ).pack(side="left", expand=True)
            
            ctk.CTkButton(
                action_frame,
                text="Execute",
                command=lambda a=action: self.execute_defense(a, threat),
                width=100,
                fg_color="#28a745"
            ).pack(side="right", padx=10)
            
    def get_contextual_actions(self, attack_type):        
        actions_map = {
            'mqtt_broker_flood': [
                {'name': 'Rate Limiting', 'description': 'Limit MQTT message rate', 'action': 'rate_limit'},
                {'name': 'Block Source', 'description': 'Block attacking IP', 'action': 'block_ip'},
                {'name': 'Reset Broker', 'description': 'Reset MQTT connections', 'action': 'reset_mqtt'}
            ],
            'command_injection': [
                {'name': 'Quarantine', 'description': 'Isolate affected device', 'action': 'quarantine'},
                {'name': 'Input Validation', 'description': 'Enable strict validation', 'action': 'validate'},
                {'name': 'Patch Device', 'description': 'Apply security patch', 'action': 'patch'}
            ],
            'arp_spoofing': [
                {'name': 'ARP Protection', 'description': 'Enable ARP inspection', 'action': 'arp_protect'},
                {'name': 'Static ARP', 'description': 'Set static ARP entries', 'action': 'static_arp'},
                {'name': 'Segment Network', 'description': 'Isolate network segment', 'action': 'segment'}
            ],
            'port_scan_stealth': [
                {'name': 'Block Scanner', 'description': 'Block scanning IP', 'action': 'block_scan'},
                {'name': 'Close Ports', 'description': 'Close unused ports', 'action': 'close_ports'},
                {'name': 'Enable IDS', 'description': 'Activate intrusion detection', 'action': 'enable_ids'}
            ],
            'default_credentials': [
                {'name': 'Force Reset', 'description': 'Force password change', 'action': 'force_reset'},
                {'name': 'Lock Account', 'description': 'Lock default accounts', 'action': 'lock_account'},
                {'name': 'Enable MFA', 'description': 'Require multi-factor auth', 'action': 'enable_mfa'}
            ]
        }
        
        return actions_map.get(attack_type, [
            {'name': 'Block Source', 'description': 'Block attack source', 'action': 'block'},
            {'name': 'Increase Monitoring', 'description': 'Enhanced monitoring', 'action': 'monitor'},
            {'name': 'Alert Team', 'description': 'Notify security team', 'action': 'alert'}
        ])
        
    def execute_defense(self, action, threat):       
        defense_msg = {
            'action': action['action'],
            'threat_id': threat.get('id', 'unknown'),
            'threat_type': threat['type'],
            'timestamp': time.time()
        }
        
        self.mqtt_client.publish(f"dcis/defense/{action['action']}", json.dumps(defense_msg), qos=2)
        
        self.add_activity(f"🛡️ Executed: {action['name']} against {threat['type']}")
        self.add_defense_log(f"{datetime.now().strftime('%H:%M:%S')} - {action['name']} executed")
        
       
        threat['status'] = 'MITIGATED'
        self.update_threat_display()
        
       
        self.show_secure_state()
        self.threat_status_label.configure(
            text="🟢 Threat mitigated successfully",
            text_color="#2ea043"
        )
        
    def execute_defense_action(self, action, threat_id=None):       
        threat = None
        if threat_id:
            threat = next((t for t in self.live_threats if t['id'] == threat_id), None)
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        if action == "block_source" and threat:
            
            source_ip = threat.get('source', 'unknown')
            self.blocked_ips.add(source_ip)
            
            
            for t in self.live_threats:
                if t.get('source') == source_ip and t['status'] == 'ACTIVE':
                    t['status'] = 'BLOCKED'
            
            self.add_defense_log(f"{timestamp} - BLOCKED IP {source_ip} permanently")
            messagebox.showinfo("Defense Action", f"IP {source_ip} has been permanently blocked")
        
       
        self.update_threat_display()
        if hasattr(self, 'update_mesh_topology'):
            self.update_mesh_topology()
        
    def execute_defense_and_update(self, action, threat):       
        self.execute_defense(action, threat)
        
        
        for t in self.live_threats:
            if t['id'] == threat['id']:
                t['status'] = 'MITIGATED'
                break
        
        
        self.update_threat_display()
        self.update_metrics()
        
        
        active_threats = [t for t in self.live_threats if t['status'] == 'ACTIVE']
        
        if active_threats:
          
            self.update_defense_center_for_threat(active_threats[0])
        else:
            
            self.show_secure_state()
            self.threat_status_label.configure(
                text="🟢 All threats mitigated",
                text_color="#2ea043"
            )

            
    def update_device_discovery(self):        
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        
        all_devices = []
        healthy = 0
        
        
        for coord_id, data in self.components['coordinators'].items():
            all_devices.append(('🎛️ Coordinator', coord_id, data))
        
        for node_id, data in self.components['nodes'].items():
            all_devices.append(('📡 Virtual Node', node_id, data))
        
        for esp_id, data in self.components['esp32'].items():
            all_devices.append(('📟 ESP32', esp_id, data))
        
        
        for device_type, device_id, data in all_devices:
            last_seen = data.get('last_seen', 0)
            age = time.time() - last_seen
            
            if age < 60:
                health = "🟢 Healthy"
                healthy += 1
            elif age < 300:
                health = "🟡 Warning"
            else:
                health = "🔴 Critical"
            
            last_seen_str = f"{int(age)}s ago" if age < 3600 else "Long ago"
            monitoring = f"Monitoring {len(all_devices)-1} devices"
            
            values = (
                device_type,
                device_id[:20],
                data.get('ip', 'Unknown'),
                health,
                last_seen_str,
                monitoring
            )
            self.device_tree.insert('', 'end', values=values)
        
        
        total = len(all_devices)
        connections = (total * (total - 1)) // 2 if total > 1 else 0
        
        self.device_stats["Coordinators"].value_label.configure(text=str(len(self.components['coordinators'])))
        self.device_stats["Virtual Nodes"].value_label.configure(text=str(len(self.components['nodes'])))
        self.device_stats["ESP32 Devices"].value_label.configure(text=str(len(self.components['esp32'])))
        self.device_stats["Healthy"].value_label.configure(text=str(healthy))
        self.device_stats["Cross-Links"].value_label.configure(text=str(connections))
        
    def on_mqtt_connect(self, client, userdata, flags, rc):        
        if rc == 0:
            logging.info("Connected to MQTT broker")
            subscriptions = [
                "dcis/nodes/+/heartbeat",
                "dcis/coordinators/+/heartbeat",
                "dcis/esp32/+/status",
                "dcis/attacks/real_time",
                "dcis/threats/+",
                "dcis/defense/+",
                "dcis/dashboard/consensus_result"
            ]
            
            for topic in subscriptions:
                client.subscribe(topic)
                
            self.add_activity("✓ Connected to MQTT broker")
        else:
            self.add_activity(f"✗ MQTT connection failed: {rc}")
            
    def on_mqtt_message(self, client, userdata, msg):      
        try:
            topic = msg.topic
            data = json.loads(msg.payload.decode())
            
            if "/coordinators/" in topic and "/heartbeat" in topic:
                self.handle_coordinator_heartbeat(data)
            elif "/nodes/" in topic and "/heartbeat" in topic:
                self.handle_node_heartbeat(data)
            elif "/esp32/" in topic:
                self.handle_esp32_status(data)
            elif "/attacks/" in topic or "/threats/" in topic:
                self.handle_threat(data)
            elif "/defense/" in topic:
                self.handle_defense(data)
            elif "consensus_result" in topic:
                self.handle_consensus_result(data)
                
        except Exception as e:
            logging.error(f"Message processing error: {e}")
            
    def handle_coordinator_heartbeat(self, data):        
        coord_id = data.get('coordinator_id')
        if coord_id:
            self.components['coordinators'][coord_id] = {
                'ip': data.get('ip'),
                'last_seen': time.time()
            }
            self.add_activity(f"🎛️ Coordinator active: {coord_id}")
            
    def handle_node_heartbeat(self, data):        
        node_id = data.get('node_id')
        if node_id:
            self.components['nodes'][node_id] = {
                'ip': data.get('ip'),
                'last_seen': time.time()
            }
            self.node_heartbeats[node_id] = time.time() 
            self.add_activity(f"📡 Node active: {node_id}")
            
    def handle_esp32_status(self, data):       
        esp_id = data.get('esp32_id')
        if esp_id:
            self.components['esp32'][esp_id] = {
                'ip': data.get('ip'),
                'rssi': data.get('wifi_rssi'),
                'last_seen': time.time()
            }
            self.esp32_heartbeats[esp_id] = time.time()
            self.add_activity(f"📟 ESP32 active: {esp_id}")
            
    def handle_threat(self, data):        
        source_ip = data.get('source', 'unknown')
        if source_ip in self.blocked_ips:
            self.add_activity(f"🚫 Blocked threat from banned IP: {source_ip}")
            self.add_defense_log(f"BLOCKED: Threat attempt from banned IP {source_ip}")
            return  
        
        threat_type = data.get('threat_type', data.get('attack_type', 'unknown'))
        target = data.get('target', data.get('target_ip', '192.168.0.100'))
        threat_signature = f"{threat_type}_{target}_{source_ip}"
        
        
        current_time = time.time()
        if threat_signature in self.threat_signatures:
            last_seen = self.threat_signatures[threat_signature]
            if current_time - last_seen < 5: 
                return 
        
        self.threat_signatures[threat_signature] = current_time
        
      
        threat_id = data.get('threat_id', f"threat_{int(time.time() * 1000)}")
       
        threat = {
            'id': threat_id,
            'timestamp': datetime.now(),
            'source': source_ip,
            'target': target,
            'type': threat_type,
            'severity': data.get('severity', 'MEDIUM'),
            'consensus': 'Pending',
            'status': 'ACTIVE',
            'detection_start': current_time,
            'response_time': 0,
            'consensus_requested': False
        }
    
        self.live_threats.append(threat)
        
        if not hasattr(self, 'pending_consensus'):
            self.pending_consensus = {}
        self.pending_consensus[threat_id] = threat
        
        self.request_consensus_validation(threat)
        
        self.add_activity(f"⚠️ Threat: {threat['type']} → {threat['target']}")
     
        self.root.after(0, self.update_threat_display)
       
        if hasattr(self, 'update_mesh_topology'):
            self.root.after(0, self.update_mesh_topology)
        
        if threat['severity'].upper() in ['HIGH', 'CRITICAL']:
            self.root.after(0, lambda: self.update_defense_center_for_threat(threat))
            
    def request_consensus_validation(self, threat):     
        threat_data = threat.copy()
        if isinstance(threat_data.get('timestamp'), datetime):
            threat_data['timestamp'] = threat_data['timestamp'].isoformat()
        
        request = {
            'validation_id': f"val_{threat['id']}",
            'threat_data': threat_data,
            'requester': 'dashboard',
            'timestamp': time.time()
        }
        
        self.mqtt_client.publish(
            "dcis/consensus/request",
            json.dumps(request, cls=DateTimeEncoder)
        )
        threat['consensus_requested'] = True
        
    def handle_defense(self, data):    
        defense = {
            'action': data.get('action'),
            'threat_id': data.get('threat_id'),
            'timestamp': datetime.now()
        }
        
        self.defense_actions.append(defense)
        self.add_defense_log(f"{defense['timestamp'].strftime('%H:%M:%S')} - {defense['action']}")
        
    def handle_consensus_result(self, data):       
        threat_id = data.get('threat_id')
        
        if hasattr(self, 'pending_consensus') and threat_id in self.pending_consensus:
            threat = self.pending_consensus[threat_id]
     
            threat['response_time'] = time.time() - threat['detection_start']
          
            threat['consensus'] = 'Confirmed' if data.get('consensus_reached') else 'Rejected'
            threat['consensus_confidence'] = data.get('confidence', 0)
            
            
            for t in self.live_threats:
                if t['id'] == threat_id:
                    t.update(threat)
                    break
            
            if threat['consensus'] == 'Confirmed':
                self.trigger_auto_defense(threat)
            
            del self.pending_consensus[threat_id]
            self.update_threat_display()
            self.calculate_real_metrics()   
    
    def trigger_auto_defense(self, threat):        
        self.update_defense_center_for_threat(threat)
        
        
        if threat['severity'].upper() in ['HIGH', 'CRITICAL']:
            actions = self.get_contextual_actions(threat['type'])
            if actions:
                
                self.execute_defense(actions[0], threat)
                self.add_activity(f"🛡️ AUTO-DEFENSE: {actions[0]['name']} against {threat['type']}")
                self.add_defense_log(f"AUTO: {actions[0]['name']} executed for threat {threat['id'][:8]}")
    
    def update_defense_center_for_threat(self, threat):    
        if hasattr(self, 'defense_content'):
     
            for widget in self.defense_content.winfo_children():
                widget.pack_forget()
            
   
            self.threat_status_label.configure(
                text=f"🔴 ACTIVE THREAT: {threat['type']} - Severity: {threat['severity'].upper()}",
                text_color="#da3633"
            )
            
            threat_frame = ctk.CTkFrame(self.defense_content)
            threat_frame.pack(fill="both", expand=True, padx=20, pady=20)
            
            ctk.CTkLabel(
                threat_frame,
                text=f"🚨 {threat['type'].upper()} DETECTED",
                font=("Arial", 18, "bold"),
                text_color="#da3633"
            ).pack(pady=15)
            
        
            details_frame = ctk.CTkFrame(threat_frame)
            details_frame.pack(fill="x", padx=20, pady=10)
            
            details = [
                ("Source", threat['source']),
                ("Target", threat['target']),
                ("Severity", threat['severity'].upper()),
                ("Consensus", threat['consensus']),
                ("Status", threat['status'])
            ]
            
            for label, value in details:
                row = ctk.CTkFrame(details_frame, fg_color="transparent")
                row.pack(fill="x", pady=2)
                ctk.CTkLabel(row, text=f"{label}:", width=100, anchor="w").pack(side="left")
                ctk.CTkLabel(row, text=value, text_color="#1f6feb").pack(side="left")
            
  
            actions = self.get_contextual_actions(threat['type'])
            
            ctk.CTkLabel(
                threat_frame,
                text="Recommended Defense Actions:",
                font=("Arial", 14, "bold")
            ).pack(pady=(20, 10))
            
 
            for action in actions:
                action_frame = ctk.CTkFrame(threat_frame)
                action_frame.pack(fill="x", padx=10, pady=5)
                
                ctk.CTkLabel(
                    action_frame,
                    text=f"🛡️ {action['name']}",
                    font=("Arial", 12, "bold")
                ).pack(side="left", padx=10)
                
                ctk.CTkLabel(
                    action_frame,
                    text=action['description'],
                    font=("Arial", 11),
                    text_color="gray"
                ).pack(side="left", expand=True)
                
                ctk.CTkButton(
                    action_frame,
                    text="Execute",
                    command=lambda a=action, t=threat: self.execute_defense_and_update(a, t),
                    width=100,
                    fg_color="#28a745"
                ).pack(side="right", padx=10)
        
    def add_activity(self, message):  
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            if hasattr(self, 'activity_text'):
                self.activity_text.insert("end", f"[{timestamp}] {message}\n")
                self.activity_text.see("end")
        except:
            pass
        
    def add_defense_log(self, message):
        try:
            if hasattr(self, 'defense_log') and self.root.winfo_exists():
                self.defense_log.insert("end", message + "\n")
                self.defense_log.see("end")
        except (tk.TclError, AttributeError):
            pass
        
    def update_threat_display(self): 
        try:  
            for item in self.threat_tree.get_children():
                self.threat_tree.delete(item)
            

            display_threats = list(self.live_threats)[-50:]
            
            for threat in reversed(display_threats):

                tags = []
                if threat['status'] == 'MITIGATED':
                    tags = ['mitigated']
                elif threat['severity'].upper() == 'CRITICAL':
                    tags = ['critical']
                elif threat['severity'].upper() == 'HIGH':
                    tags = ['high']
                

                if isinstance(threat['timestamp'], datetime):
                    time_str = threat['timestamp'].strftime('%H:%M:%S')
                else:
                    time_str = str(threat['timestamp'])
                
                values = (
                    time_str,
                    str(threat.get('source', 'unknown'))[:20],
                    str(threat.get('target', 'unknown'))[:20],
                    str(threat.get('type', 'unknown'))[:20],
                    threat.get('severity', 'MEDIUM').upper(),
                    threat.get('consensus', 'Pending'),
                    threat.get('status', 'ACTIVE')
                )
                
                self.threat_tree.insert('', 'end', values=values, tags=tags)
            

            self.threat_tree.tag_configure('mitigated', foreground='#2ea043')
            self.threat_tree.tag_configure('critical', foreground='#da3633')
            self.threat_tree.tag_configure('high', foreground='#fd7e14')
            
        except Exception as e:
            logging.error(f"Error updating threat display: {e}")

    def check_coordinator_status(self): 
        for coord in self.components['coordinators'].values():
            last_seen = time.time() - coord.get('last_seen', 0)
            if last_seen < 30:  
                print(f"✓ Coordinator {coord.get('coordinator_id')} active")
            else:
                print(f"✗ Coordinator {coord.get('coordinator_id')} inactive")
            
    def update_metrics(self):  
        self.metric_cards["Active Nodes"].value_label.configure(text=str(len(self.components['nodes'])))
        self.metric_cards["Coordinators"].value_label.configure(text=str(len(self.components['coordinators'])))
        self.metric_cards["ESP32 Devices"].value_label.configure(text=str(len(self.components['esp32'])))
        self.metric_cards["Active Threats"].value_label.configure(
            text=str(len([t for t in self.live_threats if t['status'] == 'ACTIVE']))
        )
        self.metric_cards["Defense Actions"].value_label.configure(text=str(len(self.defense_actions)))
        self.metric_cards["Total Devices"].value_label.configure(
            text=str(len(self.components['coordinators']) + len(self.components['nodes']) + len(self.components['esp32']))
        )
        
    def update_health(self):

        health_text = f"""
System Health Report
═══════════════════════════════

User: {self.user_name}
Uptime: {time.strftime('%H:%M:%S', time.gmtime(time.time() - self.start_time))}

Components:
• Coordinators: {len(self.components['coordinators'])}
• Virtual Nodes: {len(self.components['nodes'])}
• ESP32 Devices: {len(self.components['esp32'])}

Security Status:
• Active Threats: {len([t for t in self.live_threats if t['status'] == 'ACTIVE'])}
• Mitigated: {len([t for t in self.live_threats if t['status'] == 'MITIGATED'])}
• Defense Actions: {len(self.defense_actions)}

Mesh Status:
• Cross-monitoring active
• All components connected
• Byzantine consensus enabled
"""
        
        self.health_text.delete("1.0", tk.END)
        self.health_text.insert("1.0", health_text)
        
    def update_statistics(self):
        stats = f"""
═══════════════════════════════════════════════
           SYSTEM PERFORMANCE METRICS
═══════════════════════════════════════════════

MESH NETWORK:
  • Coordinators: {len(self.components['coordinators'])}
  • Virtual Nodes: {len(self.components['nodes'])}
  • ESP32 Devices: {len(self.components['esp32'])}
  • Cross-Monitoring: TRUE MESH ACTIVE

THREAT DETECTION:
  • Detection Rate: {self.metrics['detection_rate']}%
  • Response Time: {self.metrics['response_time']}s
  • False Positive: {self.metrics['false_positive_rate']}%
  • Consensus: {self.metrics['consensus_threshold']}%

ATTACKS:
  • Total: {len(self.live_threats)}
  • Active: {len([t for t in self.live_threats if t['status'] == 'ACTIVE'])}
  • Mitigated: {len([t for t in self.live_threats if t['status'] == 'MITIGATED'])}

DEFENSE:
  • Actions Executed: {len(self.defense_actions)}
  • Auto-Response: Enabled
  • Manual Override: Available

═══════════════════════════════════════════════
"""
        
        self.stats_text.delete("1.0", tk.END)
        self.stats_text.insert("1.0", stats)
        
    
    def safe_update(self): 
        try:
            if self.root.winfo_exists():
                self.update_metrics()
                self.update_health()
                self.update_statistics()
                self.draw_true_mesh_topology()
                self.update_device_discovery()
                self.calculate_real_metrics()
        except (tk.TclError, RuntimeError):
            pass
                
    def connect_mqtt(self):
        try:
            self.mqtt_client.connect(self.broker_host, 1883, 60)
            self.mqtt_client.loop_start()
        except Exception as e:
            self.add_activity(f"✗ MQTT error: {e}")
            
 
    def increase_monitoring(self):
        self.execute_defense_action("increase_monitoring")
        
    def system_scan(self):
        self.execute_defense_action("system_scan")
        
    def update_rules(self):
        self.execute_defense_action("update_rules")
        
    def execute_threat_defense(self, attack_type, window):
        actions = self.get_contextual_actions(attack_type)
        if actions:
            self.execute_defense(actions[0], {'type': attack_type, 'id': 'manual'})
            window.destroy()
            
    def quick_defend(self):
        selection = self.threat_tree.selection()
        if selection:
            item = self.threat_tree.item(selection[0])
            values = item['values']
            attack_type = values[3]
            actions = self.get_contextual_actions(attack_type)
            if actions:
                self.execute_defense(actions[0], {'type': attack_type, 'id': 'quick'})
                
    def copy_threat_info(self):
        selection = self.threat_tree.selection()
        if selection:
            item = self.threat_tree.item(selection[0])
            values = item['values']
            info = f"Threat: {values[3]} | Target: {values[2]} | Severity: {values[4]}"
            self.root.clipboard_clear()
            self.root.clipboard_append(info)
            
    def execute_defense_action(self, action): 
        defense_msg = {
            'action': action,
            'timestamp': time.time()
        }
        
        self.mqtt_client.publish(f"dcis/defense/{action}", json.dumps(defense_msg), qos=2)
        self.add_activity(f"🛡️ Manual: {action}")
        self.add_defense_log(f"Manual: {action}")
        
    def logout(self): 
        if messagebox.askyesno("Logout", "Are you sure?"):
            self.running = False
            self.mqtt_client.loop_stop()
            self.mqtt_client.disconnect()
            self.root.destroy()
            main()
            
    def on_closing(self):
        self.running = False
        try:
            
            if hasattr(self, 'update_job'):
                self.root.after_cancel(self.update_job)
            
            if hasattr(self, 'mqtt_client'):
                self.mqtt_client.loop_stop()
                self.mqtt_client.disconnect()
        except:
            pass
        
        try:
            self.root.quit()
            self.root.destroy()
        except:
            pass

def launch_dashboard(user_name):
    root = ctk.CTk()
    dashboard = EnhancedDCISMonitor(root, user_name)
    root.protocol("WM_DELETE_WINDOW", dashboard.on_closing)
    root.mainloop()


def main(): 
    import argparse
    
    parser = argparse.ArgumentParser(description='DCIS Enhanced Dashboard')
    parser.add_argument('--broker', default='192.168.0.221', help='MQTT broker')
    parser.add_argument('--no-auth', action='store_true', help='Skip auth')
    args = parser.parse_args()
    
    if args.no_auth:
        launch_dashboard("Demo User")
    else:
        login = LoginWindow(launch_dashboard)
        login.run()


if __name__ == "__main__":
    main()