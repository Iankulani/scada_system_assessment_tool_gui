import sys
import socket
import threading
import time
import datetime
from collections import defaultdict
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import platform
import subprocess
import random
import json
import os
from scapy.all import sniff, IP, TCP, UDP, ICMP
import numpy as np
from tkinter import scrolledtext

class CyberGuard:
    def __init__(self):
        # Initialize threat counters
        self.threat_counts = {
            'DOS': 0,
            'DDOS': 0,
            'PortScan': 0,
            'Suspicious': 0,
            'Malformed': 0
        }
        
        # Network monitoring variables
        self.monitoring = False
        self.target_ip = ""
        self.packet_count = 0
        self.port_scan_threshold = 10  # Ports scanned within time window to trigger alert
        self.time_window = 5  # Seconds
        self.port_access_counts = defaultdict(int)
        self.ip_access_counts = defaultdict(int)
        
        # Data storage
        self.event_log = []
        self.traffic_data = {
            'TCP': 0,
            'UDP': 0,
            'ICMP': 0,
            'Other': 0
        }
        
        # Create GUI
        self.create_gui()
        
    def create_gui(self):
        """Create the main application GUI"""
        self.root = tk.Tk()
        self.root.title("SCADA SYSTEM CYBER ASSESSEMENT  TOOL")
        self.root.geometry("1200x800")
        
        # Apply purple/blue theme
        self.root.tk_setPalette(
            background='#1a1a2e',
            foreground='#e6e6e6',
            activeBackground='#4e4e8a',
            activeForeground='#e6e6e6'
        )
        
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure styles
        style.configure('TFrame', background='#1a1a2e')
        style.configure('TLabel', background='#1a1a2e', foreground='#e6e6e6')
        style.configure('TButton', background='#4e4e8a', foreground='#e6e6e6')
        style.configure('TEntry', fieldbackground='#2d2d4d', foreground='#e6e6e6')
        style.configure('TCombobox', fieldbackground='#2d2d4d', foreground='#e6e6e6')
        style.configure('TNotebook', background='#1a1a2e')
        style.configure('TNotebook.Tab', background='#4e4e8a', foreground='#e6e6e6')
        style.configure('TScrollbar', background='#4e4e8a')
        style.configure('Treeview', background='#2d2d4d', foreground='#e6e6e6', fieldbackground='#2d2d4d')
        style.map('Treeview', background=[('selected', '#4e4e8a')])
        
        # Create menu bar
        self.create_menu()
        
        # Create main notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill='both')
        
        # Create dashboard tab
        self.create_dashboard_tab()
        
        # Create monitoring tab
        self.create_monitoring_tab()
        
        # Create terminal tab
        self.create_terminal_tab()
        
        # Create charts tab
        self.create_charts_tab()
        
        # Create logs tab
        self.create_logs_tab()
        
        # Initialize terminal
        self.terminal_commands = {
            'help': self.terminal_help,
            'exit': self.terminal_exit,
            'ping': self.terminal_ping,
            'start': self.terminal_start_monitoring,
            'stop': self.terminal_stop_monitoring,
            'export': self.terminal_export_data,
            'view': self.terminal_view
        }
        
        # Start the GUI
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.update_dashboard()
        self.root.mainloop()
    
    def create_menu(self):
        """Create the menu bar"""
        menubar = tk.Menu(self.root)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="New Session", command=self.new_session)
        file_menu.add_command(label="Load Session", command=self.load_session)
        file_menu.add_command(label="Save Session", command=self.save_session)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.on_close)
        menubar.add_cascade(label="File", menu=file_menu)
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Dashboard", command=lambda: self.notebook.select(0))
        view_menu.add_command(label="Monitoring", command=lambda: self.notebook.select(1))
        view_menu.add_command(label="Terminal", command=lambda: self.notebook.select(2))
        view_menu.add_command(label="Charts", command=lambda: self.notebook.select(3))
        view_menu.add_command(label="Logs", command=lambda: self.notebook.select(4))
        menubar.add_cascade(label="View", menu=view_menu)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Ping Tool", command=self.open_ping_tool)
        tools_menu.add_command(label="Port Scanner", command=self.open_port_scanner)
        tools_menu.add_command(label="Packet Analyzer", command=self.open_packet_analyzer)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        
        # Settings menu
        settings_menu = tk.Menu(menubar, tearoff=0)
        settings_menu.add_command(label="Configuration", command=self.open_settings)
        settings_menu.add_command(label="Themes", command=self.open_themes)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="User Guide", command=self.open_user_guide)
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def create_dashboard_tab(self):
        """Create the dashboard tab"""
        dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(dashboard_frame, text="Dashboard")
        
        # Header
        header_frame = ttk.Frame(dashboard_frame)
        header_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(header_frame, text="CyberGuard Dashboard", font=('Helvetica', 16, 'bold')).pack(side='left')
        
        # Status indicators
        status_frame = ttk.Frame(dashboard_frame)
        status_frame.pack(fill='x', padx=10, pady=10)
        
        # Monitoring status
        self.monitor_status = tk.StringVar(value="Not Monitoring")
        ttk.Label(status_frame, text="Monitoring Status:").grid(row=0, column=0, sticky='w')
        ttk.Label(status_frame, textvariable=self.monitor_status, foreground='red').grid(row=0, column=1, sticky='w')
        
        # Target IP
        self.target_ip_var = tk.StringVar(value="None")
        ttk.Label(status_frame, text="Target IP:").grid(row=1, column=0, sticky='w')
        ttk.Label(status_frame, textvariable=self.target_ip_var).grid(row=1, column=1, sticky='w')
        
        # Threat summary
        threat_frame = ttk.LabelFrame(dashboard_frame, text="Threat Summary")
        threat_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Threat counters
        self.dos_count_var = tk.StringVar(value="0")
        self.ddos_count_var = tk.StringVar(value="0")
        self.portscan_count_var = tk.StringVar(value="0")
        self.suspicious_count_var = tk.StringVar(value="0")
        self.malformed_count_var = tk.StringVar(value="0")
        
        ttk.Label(threat_frame, text="DOS Attacks:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        ttk.Label(threat_frame, textvariable=self.dos_count_var, foreground='red').grid(row=0, column=1, sticky='w', padx=5, pady=5)
        
        ttk.Label(threat_frame, text="DDOS Attacks:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        ttk.Label(threat_frame, textvariable=self.ddos_count_var, foreground='red').grid(row=1, column=1, sticky='w', padx=5, pady=5)
        
        ttk.Label(threat_frame, text="Port Scans:").grid(row=2, column=0, sticky='w', padx=5, pady=5)
        ttk.Label(threat_frame, textvariable=self.portscan_count_var, foreground='orange').grid(row=2, column=1, sticky='w', padx=5, pady=5)
        
        ttk.Label(threat_frame, text="Suspicious Activities:").grid(row=3, column=0, sticky='w', padx=5, pady=5)
        ttk.Label(threat_frame, textvariable=self.suspicious_count_var, foreground='yellow').grid(row=3, column=1, sticky='w', padx=5, pady=5)
        
        ttk.Label(threat_frame, text="Malformed Packets:").grid(row=4, column=0, sticky='w', padx=5, pady=5)
        ttk.Label(threat_frame, textvariable=self.malformed_count_var, foreground='orange').grid(row=4, column=1, sticky='w', padx=5, pady=5)
        
        # Quick actions
        action_frame = ttk.Frame(dashboard_frame)
        action_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(action_frame, text="Start Monitoring", command=self.start_monitoring_gui).grid(row=0, column=0, padx=5)
        ttk.Button(action_frame, text="Stop Monitoring", command=self.stop_monitoring).grid(row=0, column=1, padx=5)
        ttk.Button(action_frame, text="View Logs", command=lambda: self.notebook.select(4)).grid(row=0, column=2, padx=5)
        ttk.Button(action_frame, text="Generate Report", command=self.generate_report).grid(row=0, column=3, padx=5)
    
    def create_monitoring_tab(self):
        """Create the monitoring configuration tab"""
        monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(monitor_frame, text="Monitoring")
        
        # Target IP configuration
        ip_frame = ttk.LabelFrame(monitor_frame, text="Target IP Configuration")
        ip_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(ip_frame, text="Target IP Address:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.ip_entry = ttk.Entry(ip_frame)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5, sticky='ew')
        
        ttk.Button(ip_frame, text="Set Target", command=self.set_target_ip).grid(row=0, column=2, padx=5, pady=5)
        
        # Monitoring controls
        control_frame = ttk.LabelFrame(monitor_frame, text="Monitoring Controls")
        control_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(control_frame, text="Start Monitoring", command=self.start_monitoring_gui).pack(side='left', padx=5, pady=5)
        ttk.Button(control_frame, text="Stop Monitoring", command=self.stop_monitoring).pack(side='left', padx=5, pady=5)
        
        # Threshold configuration
        threshold_frame = ttk.LabelFrame(monitor_frame, text="Detection Thresholds")
        threshold_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(threshold_frame, text="Port Scan Threshold (ports/min):").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.port_scan_threshold_entry = ttk.Entry(threshold_frame)
        self.port_scan_threshold_entry.insert(0, str(self.port_scan_threshold))
        self.port_scan_threshold_entry.grid(row=0, column=1, padx=5, pady=5, sticky='w')
        
        ttk.Label(threshold_frame, text="DOS Threshold (requests/sec):").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.dos_threshold_entry = ttk.Entry(threshold_frame)
        self.dos_threshold_entry.insert(0, "100")
        self.dos_threshold_entry.grid(row=1, column=1, padx=5, pady=5, sticky='w')
        
        ttk.Button(threshold_frame, text="Apply Thresholds", command=self.apply_thresholds).grid(row=2, column=0, columnspan=2, pady=5)
        
        # Network interface selection
        if_frame = ttk.LabelFrame(monitor_frame, text="Network Interface")
        if_frame.pack(fill='x', padx=10, pady=10)
        
        self.iface_var = tk.StringVar()
        if platform.system() == "Linux":
            self.iface_var.set("eth0")
        elif platform.system() == "Windows":
            self.iface_var.set("Ethernet")
        else:
            self.iface_var.set("en0")
        
        ttk.Label(if_frame, text="Select Interface:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        ttk.Entry(if_frame, textvariable=self.iface_var).grid(row=0, column=1, padx=5, pady=5, sticky='ew')
    
    def create_terminal_tab(self):
        """Create the terminal tab"""
        terminal_frame = ttk.Frame(self.notebook)
        self.notebook.add(terminal_frame, text="Terminal")
        
        # Terminal output
        self.terminal_output = scrolledtext.ScrolledText(
            terminal_frame,
            wrap=tk.WORD,
            width=100,
            height=25,
            bg='#2d2d4d',
            fg='#e6e6e6',
            insertbackground='white'
        )
        self.terminal_output.pack(expand=True, fill='both', padx=10, pady=10)
        self.terminal_output.insert('end', "CyberGuard Terminal - Type 'help' for commands\n")
        self.terminal_output.config(state='disabled')
        
        # Terminal input
        input_frame = ttk.Frame(terminal_frame)
        input_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        self.terminal_prompt = ttk.Label(input_frame, text=">>>")
        self.terminal_prompt.pack(side='left')
        
        self.terminal_input = ttk.Entry(input_frame)
        self.terminal_input.pack(side='left', expand=True, fill='x', padx=5)
        self.terminal_input.bind('<Return>', self.process_terminal_command)
        
        ttk.Button(input_frame, text="Send", command=lambda: self.process_terminal_command(None)).pack(side='left')
    
    def create_charts_tab(self):
        """Create the data visualization tab"""
        charts_frame = ttk.Frame(self.notebook)
        self.notebook.add(charts_frame, text="Charts")
        
        # Threat distribution pie chart
        pie_frame = ttk.LabelFrame(charts_frame, text="Threat Distribution")
        pie_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.pie_fig, self.pie_ax = plt.subplots(figsize=(6, 4), facecolor='#1a1a2e')
        self.pie_ax.set_facecolor('#1a1a2e')
        self.pie_canvas = FigureCanvasTkAgg(self.pie_fig, master=pie_frame)
        self.pie_canvas.get_tk_widget().pack(fill='both', expand=True)
        
        # Traffic composition bar chart
        bar_frame = ttk.LabelFrame(charts_frame, text="Traffic Composition")
        bar_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.bar_fig, self.bar_ax = plt.subplots(figsize=(6, 4), facecolor='#1a1a2e')
        self.bar_ax.set_facecolor('#1a1a2e')
        self.bar_canvas = FigureCanvasTkAgg(self.bar_fig, master=bar_frame)
        self.bar_canvas.get_tk_widget().pack(fill='both', expand=True)
        
        # Update charts initially
        self.update_charts()
    
    def create_logs_tab(self):
        """Create the event logs tab"""
        logs_frame = ttk.Frame(self.notebook)
        self.notebook.add(logs_frame, text="Logs")
        
        # Log table
        columns = ("timestamp", "event_type", "source_ip", "details")
        self.log_tree = ttk.Treeview(
            logs_frame,
            columns=columns,
            show='headings',
            selectmode='browse',
            height=20
        )
        
        # Configure columns
        self.log_tree.heading("timestamp", text="Timestamp")
        self.log_tree.heading("event_type", text="Event Type")
        self.log_tree.heading("source_ip", text="Source IP")
        self.log_tree.heading("details", text="Details")
        
        self.log_tree.column("timestamp", width=150)
        self.log_tree.column("event_type", width=100)
        self.log_tree.column("source_ip", width=120)
        self.log_tree.column("details", width=400)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(logs_frame, orient='vertical', command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack widgets
        self.log_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Log controls
        control_frame = ttk.Frame(logs_frame)
        control_frame.pack(fill='x', padx=10, pady=10)
        
        ttk.Button(control_frame, text="Clear Logs", command=self.clear_logs).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Export Logs", command=self.export_logs).pack(side='left', padx=5)
        ttk.Button(control_frame, text="Refresh", command=self.update_logs).pack(side='left', padx=5)
    
    def process_terminal_command(self, event):
        """Process commands entered in the terminal"""
        command = self.terminal_input.get()
        self.terminal_input.delete(0, 'end')
        
        self.terminal_output.config(state='normal')
        self.terminal_output.insert('end', f">>> {command}\n")
        
        # Parse command
        parts = command.split()
        if not parts:
            self.terminal_output.insert('end', "")
            self.terminal_output.config(state='disabled')
            self.terminal_output.see('end')
            return
            
        cmd = parts[0].lower()
        args = parts[1:]
        
        if cmd in self.terminal_commands:
            try:
                self.terminal_commands[cmd](args)
            except Exception as e:
                self.terminal_output.insert('end', f"Error: {str(e)}\n")
        else:
            self.terminal_output.insert('end', f"Unknown command: {cmd}. Type 'help' for available commands.\n")
        
        self.terminal_output.config(state='disabled')
        self.terminal_output.see('end')
    
    def terminal_help(self, args):
        """Display help for terminal commands"""
        help_text = """
Available commands:
- help: Display this help message
- exit: Exit the application
- ping <IP>: Ping an IP address
- start <IP>: Start monitoring an IP address
- stop: Stop monitoring
- export <filename>: Export data to file
- view <logs|charts>: View logs or charts
"""
        self.terminal_output.insert('end', help_text)
    
    def terminal_exit(self, args):
        """Exit the application from terminal"""
        self.on_close()
    
    def terminal_ping(self, args):
        """Ping an IP address from terminal"""
        if not args:
            self.terminal_output.insert('end', "Usage: ping <IP>\n")
            return
            
        ip = args[0]
        self.terminal_output.insert('end', f"Pinging {ip}...\n")
        
        try:
            param = '-n' if platform.system().lower() == 'windows' else '-c'
            command = ['ping', param, '4', ip]
            output = subprocess.check_output(command, universal_newlines=True)
            self.terminal_output.insert('end', output + "\n")
        except subprocess.CalledProcessError as e:
            self.terminal_output.insert('end', f"Ping failed: {e.output}\n")
        except Exception as e:
            self.terminal_output.insert('end', f"Error: {str(e)}\n")
    
    def terminal_start_monitoring(self, args):
        """Start monitoring from terminal"""
        if args:
            ip = args[0]
            self.ip_entry.delete(0, 'end')
            self.ip_entry.insert(0, ip)
            self.set_target_ip()
            
        self.start_monitoring_gui()
        self.terminal_output.insert('end', f"Started monitoring {self.target_ip}\n")
    
    def terminal_stop_monitoring(self, args):
        """Stop monitoring from terminal"""
        self.stop_monitoring()
        self.terminal_output.insert('end', "Monitoring stopped\n")
    
    def terminal_export_data(self, args):
        """Export data from terminal"""
        filename = "cyberguard_export.json"
        if args:
            filename = args[0]
            
        self.export_data(filename)
        self.terminal_output.insert('end', f"Data exported to {filename}\n")
    
    def terminal_view(self, args):
        """View different sections from terminal"""
        if not args:
            self.terminal_output.insert('end', "Usage: view <logs|charts>\n")
            return
            
        view = args[0].lower()
        if view == "logs":
            self.notebook.select(4)
            self.terminal_output.insert('end', "Showing logs\n")
        elif view == "charts":
            self.notebook.select(3)
            self.terminal_output.insert('end', "Showing charts\n")
        else:
            self.terminal_output.insert('end', f"Unknown view: {view}\n")
    
    def set_target_ip(self):
        """Set the target IP for monitoring"""
        ip = self.ip_entry.get()
        if not self.validate_ip(ip):
            messagebox.showerror("Error", "Invalid IP address format")
            return
            
        self.target_ip = ip
        self.target_ip_var.set(ip)
        self.log_event("Configuration", "System", f"Target IP set to {ip}")
    
    def validate_ip(self, ip):
        """Validate an IP address"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
    
    def start_monitoring_gui(self):
        """Start monitoring from GUI"""
        if not self.target_ip:
            messagebox.showerror("Error", "Please set a target IP first")
            return
            
        if self.monitoring:
            messagebox.showwarning("Warning", "Monitoring is already running")
            return
            
        self.monitoring = True
        self.monitor_status.set("Monitoring " + self.target_ip)
        
        # Start packet capture in a separate thread
        self.capture_thread = threading.Thread(target=self.start_packet_capture, daemon=True)
        self.capture_thread.start()
        
        self.log_event("Monitoring", "System", f"Started monitoring {self.target_ip}")
    
    def stop_monitoring(self):
        """Stop monitoring"""
        if not self.monitoring:
            return
            
        self.monitoring = False
        self.monitor_status.set("Not Monitoring")
        self.log_event("Monitoring", "System", "Monitoring stopped")
    
    def apply_thresholds(self):
        """Apply new detection thresholds"""
        try:
            port_scan_threshold = int(self.port_scan_threshold_entry.get())
            dos_threshold = int(self.dos_threshold_entry.get())
            
            if port_scan_threshold <= 0 or dos_threshold <= 0:
                raise ValueError("Thresholds must be positive integers")
                
            self.port_scan_threshold = port_scan_threshold
            self.log_event("Configuration", "System", 
                          f"Thresholds updated: Port Scan={port_scan_threshold}, DOS={dos_threshold}")
            messagebox.showinfo("Success", "Thresholds updated successfully")
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid threshold value: {str(e)}")
    
    def start_packet_capture(self):
        """Start capturing and analyzing network packets"""
        try:
            # Start sniffing packets
            sniff(prn=self.analyze_packet, 
                  filter=f"host {self.target_ip}",
                  store=0,
                  iface=self.iface_var.get())
        except Exception as e:
            self.log_event("Error", "System", f"Packet capture failed: {str(e)}")
    
    def analyze_packet(self, packet):
        """Analyze a network packet for threats"""
        if not self.monitoring:
            return
            
        self.packet_count += 1
        
        try:
            # Extract basic packet information
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Check if packet is incoming to our target
                if dst_ip == self.target_ip:
                    # Update traffic composition
                    if TCP in packet:
                        self.traffic_data['TCP'] += 1
                    elif UDP in packet:
                        self.traffic_data['UDP'] += 1
                    elif ICMP in packet:
                        self.traffic_data['ICMP'] += 1
                    else:
                        self.traffic_data['Other'] += 1
                    
                    # Check for port scanning
                    if TCP in packet:
                        port = packet[TCP].dport
                        self.port_access_counts[port] += 1
                        
                        # If many different ports are being accessed from same IP
                        if len(self.port_access_counts) > self.port_scan_threshold:
                            self.threat_counts['PortScan'] += 1
                            self.log_event("PortScan", src_ip, 
                                         f"Port scan detected from {src_ip} to {dst_ip}")
                            self.port_access_counts.clear()  # Reset counter
                    
                    # Check for DOS (many packets from same source)
                    self.ip_access_counts[src_ip] += 1
                    if self.ip_access_counts[src_ip] > 100:  # Simple threshold
                        self.threat_counts['DOS'] += 1
                        self.log_event("DOS", src_ip, 
                                     f"Possible DOS attack from {src_ip} to {dst_ip}")
                    
                    # Check for malformed packets
                    if self.is_malformed(packet):
                        self.threat_counts['Malformed'] += 1
                        self.log_event("Malformed", src_ip, 
                                       f"Malformed packet from {src_ip} to {dst_ip}")
                    
                    # Update GUI
                    if self.packet_count % 10 == 0:  # Update every 10 packets
                        self.root.after(0, self.update_dashboard)
        
        except Exception as e:
            self.log_event("Error", "System", f"Packet analysis error: {str(e)}")
    
    def is_malformed(self, packet):
        """Check if a packet is malformed"""
        # Simple checks for malformed packets
        if IP in packet:
            # Check for invalid IP header length
            if packet[IP].ihl < 5 or packet[IP].ihl > 15:
                return True
            
            # Check for invalid TCP flags combinations
            if TCP in packet:
                flags = packet[TCP].flags
                # SYN and FIN set together
                if flags & 0x03 == 0x03:
                    return True
                # FIN without ACK
                if flags & 0x01 and not flags & 0x10:
                    return True
        
        return False
    
    def log_event(self, event_type, source, details):
        """Log a security event"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.event_log.append({
            'timestamp': timestamp,
            'event_type': event_type,
            'source_ip': source,
            'details': details
        })
        
        # Update logs display if we're on the logs tab
        if self.notebook.index(self.notebook.select()) == 4:  # Logs tab is index 4
            self.root.after(0, self.update_logs)
    
    def update_dashboard(self):
        """Update the dashboard with current data"""
        self.dos_count_var.set(str(self.threat_counts['DOS']))
        self.ddos_count_var.set(str(self.threat_counts['DDOS']))
        self.portscan_count_var.set(str(self.threat_counts['PortScan']))
        self.suspicious_count_var.set(str(self.threat_counts['Suspicious']))
        self.malformed_count_var.set(str(self.threat_counts['Malformed']))
        
        # Update charts periodically
        if random.random() < 0.1:  # 10% chance to update charts each call
            self.update_charts()
    
    def update_charts(self):
        """Update the data visualization charts"""
        # Update threat distribution pie chart
        self.pie_ax.clear()
        
        labels = ['DOS', 'DDOS', 'PortScan', 'Suspicious', 'Malformed']
        sizes = [self.threat_counts[label] for label in labels]
        colors = ['#ff6b6b', '#ffa502', '#2ed573', '#1e90ff', '#7d5fff']
        
        # Only show labels with non-zero values
        filtered_labels = []
        filtered_sizes = []
        filtered_colors = []
        for label, size, color in zip(labels, sizes, colors):
            if size > 0:
                filtered_labels.append(label)
                filtered_sizes.append(size)
                filtered_colors.append(color)
        
        if filtered_sizes:
            self.pie_ax.pie(filtered_sizes, labels=filtered_labels, colors=filtered_colors,
                           autopct='%1.1f%%', startangle=90, textprops={'color': 'white'})
            self.pie_ax.set_title('Threat Distribution', color='white')
        else:
            self.pie_ax.text(0.5, 0.5, 'No threat data available', 
                            ha='center', va='center', color='white')
        
        self.pie_canvas.draw()
        
        # Update traffic composition bar chart
        self.bar_ax.clear()
        
        protocols = list(self.traffic_data.keys())
        counts = list(self.traffic_data.values())
        
        if sum(counts) > 0:
            bars = self.bar_ax.bar(protocols, counts, color=['#3498db', '#9b59b6', '#2ecc71', '#f1c40f'])
            self.bar_ax.set_title('Traffic Composition', color='white')
            self.bar_ax.set_ylabel('Packet Count', color='white')
            
            # Set colors for axes
            self.bar_ax.tick_params(axis='x', colors='white')
            self.bar_ax.tick_params(axis='y', colors='white')
            
            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                self.bar_ax.text(bar.get_x() + bar.get_width()/2., height,
                                f'{int(height)}', 
                                ha='center', va='bottom', color='white')
        else:
            self.bar_ax.text(0.5, 0.5, 'No traffic data available', 
                            ha='center', va='center', color='white')
        
        self.bar_canvas.draw()
    
    def update_logs(self):
        """Update the logs display"""
        # Clear current logs
        for item in self.log_tree.get_children():
            self.log_tree.delete(item)
        
        # Add new logs (show most recent first)
        for log in reversed(self.event_log[-100:]):  # Show last 100 entries
            self.log_tree.insert("", "end", values=(
                log['timestamp'],
                log['event_type'],
                log['source_ip'],
                log['details']
            ))
    
    def clear_logs(self):
        """Clear all logged events"""
        self.event_log.clear()
        self.update_logs()
    
    def export_logs(self):
        """Export logs to a file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.event_log, f, indent=2)
                messagebox.showinfo("Success", f"Logs exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export logs: {str(e)}")
    
    def export_data(self, filename=None):
        """Export all data to a file"""
        if not filename:
            filename = filedialog.asksaveasfilename(
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            if not filename:
                return
        
        data = {
            'threat_counts': self.threat_counts,
            'traffic_data': self.traffic_data,
            'event_log': self.event_log,
            'target_ip': self.target_ip,
            'monitoring': self.monitoring,
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            self.log_event("Error", "System", f"Failed to export data: {str(e)}")
            return False
    
    def generate_report(self):
        """Generate a security report"""
        report = f"""
CyberGuard Security Report
=========================
Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Target IP: {self.target_ip}
Monitoring Status: {'Active' if self.monitoring else 'Inactive'}

Threat Summary:
- DOS Attacks: {self.threat_counts['DOS']}
- DDOS Attacks: {self.threat_counts['DDOS']}
- Port Scans: {self.threat_counts['PortScan']}
- Suspicious Activities: {self.threat_counts['Suspicious']}
- Malformed Packets: {self.threat_counts['Malformed']}

Recent Events:
"""
        for event in self.event_log[-5:]:  # Show last 5 events
            report += f"{event['timestamp']} - {event['event_type']}: {event['details']}\n"
        
        # Show report in a dialog
        report_dialog = tk.Toplevel(self.root)
        report_dialog.title("Security Report")
        report_dialog.geometry("600x400")
        
        text = tk.Text(report_dialog, wrap='word', bg='#2d2d4d', fg='white')
        text.pack(expand=True, fill='both', padx=10, pady=10)
        text.insert('1.0', report)
        text.config(state='disabled')
        
        ttk.Button(report_dialog, text="Export Report", 
                  command=lambda: self.export_report(report)).pack(pady=5)
        ttk.Button(report_dialog, text="Close", 
                  command=report_dialog.destroy).pack(pady=5)
    
    def export_report(self, report):
        """Export the report to a text file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(report)
                messagebox.showinfo("Success", f"Report exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report: {str(e)}")
    
    def new_session(self):
        """Start a new monitoring session"""
        if self.monitoring:
            self.stop_monitoring()
        
        self.threat_counts = {k: 0 for k in self.threat_counts}
        self.traffic_data = {k: 0 for k in self.traffic_data}
        self.event_log.clear()
        self.target_ip = ""
        self.target_ip_var.set("None")
        self.ip_entry.delete(0, 'end')
        
        self.update_dashboard()
        self.update_logs()
        self.update_charts()
        
        self.log_event("System", "System", "New session started")
    
    def load_session(self):
        """Load a saved session from file"""
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    data = json.load(f)
                
                self.threat_counts = data.get('threat_counts', self.threat_counts)
                self.traffic_data = data.get('traffic_data', self.traffic_data)
                self.event_log = data.get('event_log', self.event_log)
                self.target_ip = data.get('target_ip', "")
                self.target_ip_var.set(self.target_ip if self.target_ip else "None")
                self.ip_entry.delete(0, 'end')
                self.ip_entry.insert(0, self.target_ip)
                
                if data.get('monitoring', False):
                    self.start_monitoring_gui()
                else:
                    self.stop_monitoring()
                
                self.update_dashboard()
                self.update_logs()
                self.update_charts()
                
                self.log_event("System", "System", f"Session loaded from {filename}")
                messagebox.showinfo("Success", "Session loaded successfully")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load session: {str(e)}")
    
    def save_session(self):
        """Save the current session to file"""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            if self.export_data(filename):
                messagebox.showinfo("Success", f"Session saved to {filename}")
                self.log_event("System", "System", f"Session saved to {filename}")
            else:
                messagebox.showerror("Error", f"Failed to save session to {filename}")
    
    def open_ping_tool(self):
        """Open a ping utility tool"""
        ping_dialog = tk.Toplevel(self.root)
        ping_dialog.title("Ping Utility")
        ping_dialog.geometry("500x300")
        
        ttk.Label(ping_dialog, text="IP Address to Ping:").pack(pady=5)
        ip_entry = ttk.Entry(ping_dialog)
        ip_entry.pack(pady=5)
        
        output_text = scrolledtext.ScrolledText(
            ping_dialog,
            wrap=tk.WORD,
            width=60,
            height=10,
            bg='#2d2d4d',
            fg='#e6e6e6'
        )
        output_text.pack(pady=5)
        output_text.config(state='disabled')
        
        def do_ping():
            ip = ip_entry.get()
            if not ip:
                messagebox.showerror("Error", "Please enter an IP address")
                return
                
            output_text.config(state='normal')
            output_text.insert('end', f"Pinging {ip}...\n")
            output_text.see('end')
            output_text.config(state='disabled')
            
            try:
                param = '-n' if platform.system().lower() == 'windows' else '-c'
                command = ['ping', param, '4', ip]
                output = subprocess.check_output(command, universal_newlines=True)
                
                output_text.config(state='normal')
                output_text.insert('end', output + "\n")
                output_text.see('end')
                output_text.config(state='disabled')
            except subprocess.CalledProcessError as e:
                output_text.config(state='normal')
                output_text.insert('end', f"Ping failed: {e.output}\n")
                output_text.see('end')
                output_text.config(state='disabled')
            except Exception as e:
                output_text.config(state='normal')
                output_text.insert('end', f"Error: {str(e)}\n")
                output_text.see('end')
                output_text.config(state='disabled')
        
        ttk.Button(ping_dialog, text="Ping", command=do_ping).pack(pady=5)
    
    def open_port_scanner(self):
        """Open a port scanning tool"""
        scan_dialog = tk.Toplevel(self.root)
        scan_dialog.title("Port Scanner")
        scan_dialog.geometry("500x400")
        
        ttk.Label(scan_dialog, text="Target IP:").pack(pady=5)
        ip_entry = ttk.Entry(scan_dialog)
        ip_entry.pack(pady=5)
        
        ttk.Label(scan_dialog, text="Port Range (e.g., 1-100):").pack(pady=5)
        port_entry = ttk.Entry(scan_dialog)
        port_entry.pack(pady=5)
        
        output_text = scrolledtext.ScrolledText(
            scan_dialog,
            wrap=tk.WORD,
            width=60,
            height=15,
            bg='#2d2d4d',
            fg='#e6e6e6'
        )
        output_text.pack(pady=5)
        output_text.config(state='disabled')
        
        def scan_ports():
            ip = ip_entry.get()
            port_range = port_entry.get()
            
            if not ip or not port_range:
                messagebox.showerror("Error", "Please enter IP and port range")
                return
                
            try:
                start_port, end_port = map(int, port_range.split('-'))
                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    raise ValueError
            except ValueError:
                messagebox.showerror("Error", "Invalid port range format (use e.g., 1-100)")
                return
                
            output_text.config(state='normal')
            output_text.insert('end', f"Scanning ports {start_port}-{end_port} on {ip}...\n")
            output_text.see('end')
            output_text.config(state='disabled')
            
            # Simple port scanning (TCP connect)
            for port in range(start_port, end_port + 1):
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(0.5)
                        result = s.connect_ex((ip, port))
                        if result == 0:
                            output_text.config(state='normal')
                            output_text.insert('end', f"Port {port} is open\n")
                            output_text.see('end')
                            output_text.config(state='disabled')
                except Exception as e:
                    output_text.config(state='normal')
                    output_text.insert('end', f"Error scanning port {port}: {str(e)}\n")
                    output_text.see('end')
                    output_text.config(state='disabled')
                
                if not scan_dialog.winfo_exists():
                    return  # Dialog closed
            
            output_text.config(state='normal')
            output_text.insert('end', "Scan completed\n")
            output_text.see('end')
            output_text.config(state='disabled')
        
        scan_thread = threading.Thread(target=scan_ports, daemon=True)
        
        ttk.Button(scan_dialog, text="Start Scan", command=scan_thread.start).pack(pady=5)
    
    def open_packet_analyzer(self):
        """Open a simple packet analyzer tool"""
        analyzer_dialog = tk.Toplevel(self.root)
        analyzer_dialog.title("Packet Analyzer")
        analyzer_dialog.geometry("700x500")
        
        output_text = scrolledtext.ScrolledText(
            analyzer_dialog,
            wrap=tk.WORD,
            width=80,
            height=25,
            bg='#2d2d4d',
            fg='#e6e6e6'
        )
        output_text.pack(expand=True, fill='both', padx=10, pady=10)
        output_text.config(state='disabled')
        
        control_frame = ttk.Frame(analyzer_dialog)
        control_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        self.analyzer_running = False
        
        def start_analyzer():
            if self.analyzer_running:
                return
                
            self.analyzer_running = True
            start_btn.config(state='disabled')
            stop_btn.config(state='normal')
            
            output_text.config(state='normal')
            output_text.insert('end', "Starting packet capture...\n")
            output_text.see('end')
            output_text.config(state='disabled')
            
            def packet_callback(packet):
                if not self.analyzer_running:
                    return False  # Stop sniffing
                    
                output_text.config(state='normal')
                output_text.insert('end', f"{packet.summary()}\n")
                output_text.see('end')
                output_text.config(state='disabled')
                return None
            
            # Start sniffing in a separate thread
            def sniff_thread():
                sniff(prn=packet_callback, store=0, iface=self.iface_var.get())
            
            threading.Thread(target=sniff_thread, daemon=True).start()
        
        def stop_analyzer():
            self.analyzer_running = False
            start_btn.config(state='normal')
            stop_btn.config(state='disabled')
            
            output_text.config(state='normal')
            output_text.insert('end', "Packet capture stopped\n")
            output_text.see('end')
            output_text.config(state='disabled')
        
        start_btn = ttk.Button(control_frame, text="Start Capture", command=start_analyzer)
        start_btn.pack(side='left', padx=5)
        
        stop_btn = ttk.Button(control_frame, text="Stop Capture", command=stop_analyzer, state='disabled')
        stop_btn.pack(side='left', padx=5)
        
        ttk.Button(control_frame, text="Clear", command=lambda: output_text.config(state='normal') or output_text.delete('1.0', 'end') or output_text.config(state='disabled')).pack(side='right', padx=5)
    
    def open_settings(self):
        """Open the settings dialog"""
        settings_dialog = tk.Toplevel(self.root)
        settings_dialog.title("Settings")
        settings_dialog.geometry("400x300")
        
        ttk.Label(settings_dialog, text="Detection Thresholds").pack(pady=5)
        
        threshold_frame = ttk.Frame(settings_dialog)
        threshold_frame.pack(pady=5)
        
        ttk.Label(threshold_frame, text="Port Scan Threshold:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        port_scan_entry = ttk.Entry(threshold_frame)
        port_scan_entry.insert(0, str(self.port_scan_threshold))
        port_scan_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(threshold_frame, text="DOS Threshold:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
        dos_entry = ttk.Entry(threshold_frame)
        dos_entry.insert(0, "100")
        dos_entry.grid(row=1, column=1, padx=5, pady=5)
        
        def save_settings():
            try:
                self.port_scan_threshold = int(port_scan_entry.get())
                messagebox.showinfo("Success", "Settings saved")
                settings_dialog.destroy()
            except ValueError:
                messagebox.showerror("Error", "Invalid threshold value")
        
        ttk.Button(settings_dialog, text="Save", command=save_settings).pack(pady=10)
    
    def open_themes(self):
        """Open the theme selection dialog"""
        theme_dialog = tk.Toplevel(self.root)
        theme_dialog.title("Themes")
        theme_dialog.geometry("300x200")
        
        ttk.Label(theme_dialog, text="Select Theme").pack(pady=10)
        
        theme_var = tk.StringVar(value="default")
        
        themes = [
            ("Default (Purple/Blue)", "default"),
            ("Dark", "dark"),
            ("Light", "light")
        ]
        
        for text, mode in themes:
            ttk.Radiobutton(theme_dialog, text=text, variable=theme_var, value=mode).pack(anchor='w', padx=20)
        
        def apply_theme():
            theme = theme_var.get()
            if theme == "default":
                self.root.tk_setPalette(
                    background='#1a1a2e',
                    foreground='#e6e6e6',
                    activeBackground='#4e4e8a',
                    activeForeground='#e6e6e6'
                )
            elif theme == "dark":
                self.root.tk_setPalette(
                    background='#121212',
                    foreground='#ffffff',
                    activeBackground='#333333',
                    activeForeground='#ffffff'
                )
            elif theme == "light":
                self.root.tk_setPalette(
                    background='#f0f0f0',
                    foreground='#000000',
                    activeBackground='#d0d0d0',
                    activeForeground='#000000'
                )
            
            theme_dialog.destroy()
        
        ttk.Button(theme_dialog, text="Apply", command=apply_theme).pack(pady=10)
    
    def open_user_guide(self):
        """Open the user guide/documentation"""
        guide_dialog = tk.Toplevel(self.root)
        guide_dialog.title("User Guide")
        guide_dialog.geometry("600x500")
        
        text = tk.Text(guide_dialog, wrap='word', bg='#2d2d4d', fg='white')
        text.pack(expand=True, fill='both', padx=10, pady=10)
        
        guide_text = """
CyberGuard User Guide

1. Getting Started
- Set a target IP address in the Monitoring tab
- Configure detection thresholds as needed
- Click "Start Monitoring" to begin threat detection

2. Features
- Real-time threat detection (DOS, DDOS, Port Scans, etc.)
- Comprehensive logging of security events
- Visual data representation through charts
- Built-in tools (Ping, Port Scanner, Packet Analyzer)

3. Terminal Commands
- help: Show available commands
- ping <IP>: Ping an IP address
- start <IP>: Start monitoring an IP
- stop: Stop monitoring
- export <file>: Export data to file
- view <logs|charts>: Switch views

4. Threat Detection
- DOS: Detects high volume of requests from single IP
- DDOS: Detects high volume from multiple IPs (future)
- Port Scan: Detects scanning of multiple ports
- Malformed: Detects packets with invalid structure

5. Exporting Data
- Use the Export button to save logs and data
- Reports can be generated from the Dashboard
"""
        text.insert('1.0', guide_text)
        text.config(state='disabled')
        
        ttk.Button(guide_dialog, text="Close", command=guide_dialog.destroy).pack(pady=5)
    
    def show_about(self):
        """Show the about dialog"""
        messagebox.showinfo(
            "About Accurate Cyber Defense",
            "CyberGuard - Advanced Threat Detection Tool\n\n"
            "Ian Carter Kulani"
            "Version 1.0\n"
            "Developed for comprehensive network security monitoring\n"
            "Detects DOS, DDOS, Port Scans, and other threats\n"
            "\n© 2025 Accurate Cyber Defense "
        )
    
    def on_close(self):
        """Handle application close"""
        if self.monitoring:
            self.stop_monitoring()
        
        if messagebox.askokcancel("Quit", "Do you want to exit Accuerate Cyber Defense SCADA Assessemnt Tool"):
            self.root.destroy()

# Run the application
if __name__ == "__main__":
    app = CyberGuard()