import socket
import threading
import time
from queue import Queue
from ddos_detector import DDoSDetector
from collections import deque
import statistics
import errno
try:
    from scapy.all import sniff, IP, TCP
except ImportError:
    print("Scapy not installed. SYN scan detection disabled. Install with: pip install scapy")
    sniff = None

class TelnetHoneypot:
    def __init__(self, host='0.0.0.0', port=8023):
        self.host = host
        self.port = port
        self.reset_state()

    def reset_state(self):
        """Reset the honeypot state for a clean start."""
        self.server_socket = None
        self.running = False
        self.log_queue = Queue()
        self.active_threads = 0
        self.lock = threading.Lock()
        self.connection_attempts = {}
        self.syn_attempts = {}
        self.ddos_detector = DDoSDetector()
        self.connection_log = deque(maxlen=1000)
        self.packet_sizes = deque(maxlen=1000)
        self.last_analysis = time.time()

    def start(self):
        self.reset_state()
        self.ddos_detector.unblock_all()
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(500)
            self.running = True
            self.log_queue.put(("info", f"Telnet Honeypot started on {self.host}:{self.port} - Listening for connections"))
        except socket.error as e:
            error_msg = f"Failed to start honeypot: {e} (Error code: {e.errno})"
            if e.errno == errno.EACCES:
                error_msg += f" - Port {self.port} requires sudo or use a port >1024 (e.g., 8023)"
            elif e.errno == errno.EADDRINUSE:
                error_msg += f" - Port {self.port} is in use. Try: sudo fuser -k {self.port}/tcp"
            elif e.errno == errno.EADDRNOTAVAIL:
                error_msg += f" - Host {self.host} is not available on this machine"
            self.log_queue.put(("error", error_msg))
            self.running = False
            return

        ddos_thread = threading.Thread(target=self.analyze_traffic)
        ddos_thread.daemon = True
        ddos_thread.start()

        if sniff:
            syn_thread = threading.Thread(target=self.detect_syn_scans)
            syn_thread.daemon = True
            syn_thread.start()

        while self.running:
            try:
                client_socket, client_address = self.server_socket.accept()
                client_ip = client_address[0]
                if client_ip in self.ddos_detector.blocked_ips:
                    self.log_queue.put(("info", f"Dropped connection from blocked IP {client_ip}"))
                    client_socket.close()
                    continue
                with self.lock:
                    self.active_threads += 1
                    thread_id = self.active_threads
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address, thread_id)
                )
                client_thread.daemon = True
                client_thread.start()
                self.log_queue.put(("info", f"New connection accepted from {client_address[0]}:{client_address[1]} - Thread {thread_id}"))
            except Exception as e:
                if self.running:
                    self.log_queue.put(("error", f"Error accepting connection: {e}"))

    def detect_syn_scans(self):
        if not sniff:
            self.log_queue.put(("error", "Scapy not available, SYN scan detection disabled"))
            return

        def packet_callback(packet):
            if packet.haslayer(TCP) and packet[TCP].flags == 'S' and packet[TCP].dport == self.port:
                src_ip = packet[IP].src
                if src_ip in self.ddos_detector.blocked_ips:
                    self.log_queue.put(("info", f"Dropped SYN packet from blocked IP {src_ip}"))
                    return
                current_time = time.time()
                with self.lock:
                    if src_ip not in self.syn_attempts:
                        self.syn_attempts[src_ip] = []
                    self.syn_attempts[src_ip].append(current_time)
                    self.syn_attempts[src_ip] = [
                        t for t in self.syn_attempts[src_ip] if current_time - t < 60
                    ]
                    attempts = len(self.syn_attempts[src_ip])
                    self.log_queue.put(("info", f"SYN packet from {src_ip} - Total SYN attempts: {attempts}"))
                    if attempts >= 2:
                        self.log_queue.put(("scan", f"SYN scan detected from {src_ip} (SYN attempts: {attempts})"))

        try:
            sniff(filter=f"tcp dst port {self.port}", prn=packet_callback, store=False, stop_filter=lambda x: not self.running)
        except Exception as e:
            self.log_queue.put(("error", f"Error in SYN scan detection: {e}"))

    def analyze_traffic(self):
        while self.running:
            if time.time() - self.last_analysis >= 10:
                with self.lock:
                    now = time.time()
                    recent_connections = [(ip, t) for ip, t in self.connection_log if now - t < 10]
                    recent_syns = []
                    for ip, times in self.syn_attempts.items():
                        recent_syns.extend((ip, t) for t in times if now - t < 10)
                    all_connections = recent_connections + recent_syns
                    conn_rate = len(all_connections) / 10
                    avg_packet_size = statistics.mean(self.packet_sizes) if self.packet_sizes else 0
                    unique_ips = len(set(ip for ip, _ in all_connections))
                    features = [conn_rate, avg_packet_size, unique_ips]

                    self.log_queue.put(("info", f"Traffic analysis - Rate: {conn_rate:.2f}/s, Unique IPs: {unique_ips}, Avg packet size: {avg_packet_size:.2f}"))

                    is_ddos, offending_ips = self.ddos_detector.detect_ddos(features, all_connections)
                    if is_ddos:
                        self.log_queue.put(("ddos", f"DDoS attack detected! Connection rate: {conn_rate:.2f}/s, IPs: {offending_ips}"))
                        self.ddos_detector.block_ips(offending_ips)

                self.last_analysis = time.time()
            time.sleep(1)

    def detect_nmap_scan(self, client_ip):
        current_time = time.time()
        with self.lock:
            if client_ip not in self.connection_attempts:
                self.connection_attempts[client_ip] = []
            self.connection_attempts[client_ip].append(current_time)
            self.connection_attempts[client_ip] = [
                t for t in self.connection_attempts[client_ip]
                if current_time - t < 60
            ]
            attempts = len(self.connection_attempts[client_ip])
            self.log_queue.put(("info", f"Connection attempt from {client_ip} - Total attempts: {attempts}"))
            if attempts >= 2:
                return True
        return False

    def handle_client(self, client_socket, client_address, thread_id):
        client_ip = client_address[0]
        client_port = client_address[1]
        try:
            with self.lock:
                self.connection_log.append((client_ip, time.time()))

            if self.detect_nmap_scan(client_ip):
                scan_msg = f"Thread {thread_id} - Possible Nmap scan detected from {client_ip} (Attempts: {len(self.connection_attempts[client_ip])})"
                self.log_queue.put(("scan", scan_msg))

            client_socket.send(b"Welcome to Secured Telnet Server\r\n")
            client_socket.send(b"Login: ")
            client_socket.settimeout(30)
            username = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
            with self.lock:
                self.packet_sizes.append(len(username) if username else 0)

            if username:
                client_socket.send(b"Password: ")
                password = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()
                log_msg = f"Thread {thread_id} - Connection from {client_ip}:{client_port} - Username: {username} - Password: {password}"
                self.log_queue.put(("info", log_msg))
                with self.lock:
                    self.packet_sizes.append(len(password) if password else 0)
                client_socket.send(b"\r\nAuthentication failed\r\n")

            time.sleep(0.01)
            client_socket.close()
            self.log_queue.put(("info", f"Thread {thread_id} - Connection from {client_ip}:{client_port} closed"))
        except socket.timeout:
            self.log_queue.put(("info", f"Thread {thread_id} - Connection from {client_ip}:{client_port} timed out"))
            client_socket.close()
        except Exception as e:
            self.log_queue.put(("error", f"Thread {thread_id} - Error handling client {client_ip}:{client_port}: {e}"))
            client_socket.close()
        finally:
            with self.lock:
                self.active_threads -= 1

    def stop(self):
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.shutdown(socket.SHUT_RDWR)  # Force shutdown
                self.server_socket.close()
                self.log_queue.put(("info", f"Server socket closed for port {self.port}"))
            except Exception as e:
                self.log_queue.put(("error", f"Error closing socket: {e}"))
            finally:
                self.server_socket = None
        self.ddos_detector.unblock_all()
        self.log_queue.put(("info", f"Telnet Honeypot stopped - Active threads remaining: {self.active_threads}"))
        self.reset_state()

    def get_log_queue(self):
        return self.log_queue

if __name__ == "__main__":
    honeypot = TelnetHoneypot()
    try:
        honeypot.start()
    except KeyboardInterrupt:
        honeypot.stop()
