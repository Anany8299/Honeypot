from collections import Counter
import subprocess

class DDoSDetector:
    def __init__(self):
        self.blocked_ips = set()

    def detect_ddos(self, features, connection_log):
        conn_rate, avg_packet_size, unique_ips = features
        votes = []
        if conn_rate > 10 and unique_ips < 5:
            votes.append(1)
        else:
            votes.append(0)
        if conn_rate > 50:
            votes.append(1)
        else:
            votes.append(0)
        if conn_rate > 10 and avg_packet_size < 50:
            votes.append(1)
        else:
            votes.append(0)
        is_ddos = sum(votes) >= 2
        offending_ips = []
        if is_ddos:
            ip_counts = Counter(ip for ip, _ in connection_log)
            total = sum(ip_counts.values())
            offending_ips = [ip for ip, count in ip_counts.items() if count / total > 0.2]
        return is_ddos, offending_ips

    def block_ips(self, ips):
        for ip in ips:
            if ip in self.blocked_ips:
                print(f"IP {ip} already blocked")
                continue
            try:
                subprocess.run(
                    ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-p", "tcp", "--dport", "8023", "-j", "DROP"],
                    check=True
                )
                subprocess.run(
                    ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-i", "lo", "-p", "tcp", "--dport", "8023", "-j", "DROP"],
                    check=True
                )
                self.blocked_ips.add(ip)
                print(f"Blocked IP: {ip}")
            except subprocess.CalledProcessError as e:
                print(f"Error blocking IP {ip}: {e}")

    def unblock_all(self):
        try:
            subprocess.run(["sudo", "iptables", "-F"], check=True)
            self.blocked_ips.clear()
            print("Cleared all iptables rules")
        except subprocess.CalledProcessError as e:
            print(f"Error clearing iptables: {e}")
