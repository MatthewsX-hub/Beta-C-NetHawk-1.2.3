"""
Beta-C NetHawk 1.2.3 - Network Toolkit for Windows
- Live connection monitoring
- Network information
- Diagnostics (ping, DNS, TCP test, traceroute)
- Threaded port scanning
"""

import subprocess
import socket
import time
import os
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

LOG_FILE = "nethawk_log.txt" # Stores the name of the file used to record NetHawk activity.

def clear_screen():
    os.system("cls")

# Records a timestamped event in NetHawk's log file.
def log_event(event):
    """Append a timestamped message to the log file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {event}\n")

# Executes a Windows command and returns its output.
# A timeout prevents commands from running indefinitely.
def run_cmd(cmd, timeout=15):
    """Run a shell command and return output."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=timeout,
            shell=True
        )
        return result.stdout.strip() if result.stdout else result.stderr.strip()
    except subprocess.TimeoutExpired:
        return "Error: Command timed out"
    except Exception as e:
        return f"Error: {e}"

# =========================
# NETWORK INFORMATION
# =========================

# Gets the computer's hostname.
def get_hostname():
    return socket.gethostname()

# Determines the local IPv4 address used by the computer for network communication.
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) # Creates a UDP socket to determine which local network interface is being used.
        s.connect(("8.8.8.8", 80))  # Uses Google's DNS server as a destination to identify the local IP address.
        ip = s.getsockname()[0] # Retrieves the local IP address assigned to the socket.
        s.close()
        return ip
    except Exception:
        return "Unavailable"

# Displays the computer's hostname, local IP, adapter configuration,
# Default routes, and Windows network interface status.
def show_network_info():
    clear_screen()
    print("=" * 70)
    print(" Beta-C NetHawk 1.2.3 | Network Information")
    print("=" * 70)

    print(f"\nComputer Name     : {get_hostname()}")
    print(f"Local IPv4        : {get_local_ip()}")

    print("\n--- IPCONFIG ---")
    print(run_cmd("ipconfig /all"))

    print("\n--- Default Gateway / Routes ---")
    print(run_cmd("route print 0.0.0.0"))

    print("\n--- Connection Status (netsh) ---")
    print(run_cmd("netsh interface show interface"))

    input("\nPress Enter to return to menu...")

# =========================
# NETWORK DIAGNOSTICS
# =========================

# Tests whether a host can be reached using Windows ping.
def ping_host():
    host = input("Enter host to ping (e.g. 8.8.8.8 or google.com): ").strip()
    if not host:
        return
    print(f"\nPinging {host}...\n")
    print(run_cmd(f"ping -n 4 {host}", timeout=20))
    log_event(f"Ping {host}")
    input("\nPress Enter to continue...")

# Performs a DNS lookup for a given hostname.
def dns_lookup():
    host = input("Enter hostname for DNS lookup: ").strip()
    if not host:
        return
    print(f"\nDNS lookup for {host}...\n")
    print(run_cmd(f"nslookup {host}"))
    log_event(f"DNS lookup {host}")
    input("\nPress Enter to continue...")

# Tests whether a TCP connection can be established to a specific host and port.
# The measured time represents TCP connection establishment latency.
def tcp_test():
    host = input("Enter host: ").strip()
    port = input("Enter port: ").strip()
    if not host or not port:
        return
    try:
        port = int(port)
        print(f"\nTesting TCP connection to {host}:{port}...")
        start = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        result = s.connect_ex((host, port))
        latency = (time.time() - start) * 1000
        s.close()
        if result == 0:
            print(f"Success - Port {port} is open ({latency:.1f} ms)")
        else:
            print(f"Failed - Port {port} is closed or filtered")
        log_event(f"TCP test {host}:{port}")
    except Exception as e:
        print(f"Error: {e}")
    input("\nPress Enter to continue...")

# Traces the network path between the computer and the specified host.
def traceroute():
    host = input("Enter host for traceroute: ").strip()
    if not host:
        return
    print(f"\nTraceroute to {host}...\n")
    print(run_cmd(f"tracert -d -h 15 {host}", timeout=60))
    log_event(f"Traceroute {host}")
    input("\nPress Enter to continue...")

def diagnostics_menu():
    while True:
        clear_screen()
        print("=" * 70)
        print(" NetHawk 1.2.3 | Network Diagnostics")
        print("=" * 70)
        print("1. Ping a host")
        print("2. DNS lookup")
        print("3. TCP connection test")
        print("4. Traceroute")
        print("5. Back to main menu")
        choice = input("\nSelect option: ").strip()

        if choice == "1":
            ping_host()
        elif choice == "2":
            dns_lookup()
        elif choice == "3":
            tcp_test()
        elif choice == "4":
            traceroute()
        elif choice == "5":
            break

# =========================
# PORT SCANNING (THREADED)
# =========================

# Common network ports and their associated services.
COMMON_PORTS = {
    20: "FTP Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy"
}

# Tests whether a TCP port accepts a connection.
def scan_port(host, port, timeout=0.3):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except Exception:
        return False

# Tests whether a TCP port accepts a connection.
def port_scan():
    clear_screen()
    print("=" * 70)
    print(" NetHawk 1.2.3 | Port Scanner (Threaded)")
    print("=" * 70)

    host = input("Enter host to scan: ").strip()
    if not host:
        return

    print("\n1. Common ports only (fast)")
    print("2. Custom port range")
    mode = input("Select scan type: ").strip()

    ports = []
    if mode == "1":
        ports = list(COMMON_PORTS.keys())
    else:
        try:
            start_port = int(input("Start port: ").strip())
            end_port = int(input("End port: ").strip())
            if start_port > end_port or start_port < 1 or end_port > 65535:
                print("Invalid range.")
                input("Press Enter...")
                return
            ports = list(range(start_port, end_port + 1))
        except ValueError:
            print("Invalid port numbers.")
            input("Press Enter...")
            return

    print(f"\nScanning {host} ({len(ports)} ports)...\n")
    open_ports = [] # Store ports that successfully accepted a TCP connection.

    # Use multiple worker threads to scan several ports simultaneously.
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {executor.submit(scan_port, host, port): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    service = COMMON_PORTS.get(port, "Unknown")
                    print(f"  [OPEN]  Port {port:<5} ({service})")
                    open_ports.append(port)
            except Exception:
                pass

    open_ports.sort()
    print("\n" + "-" * 40)
    print(f"Scan complete. Open ports: {len(open_ports)}")
    if open_ports:
        print("Open:", ", ".join(map(str, open_ports)))
    log_event(f"Port scan {host} - open: {open_ports}")
    input("\nPress Enter to return...")

# =========================
# LIVE MONITOR
# =========================

# Retrieves the current TCP and UDP connections reported by Windows netstat.
def get_connections():
    try:
        result = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="ignore",
            timeout=10
        )
        connections = set()
        for line in result.stdout.splitlines(): # Parse each TCP or UDP entry returned by netstat.
            line = line.strip()
            if line.startswith("TCP") or line.startswith("UDP"):
                parts = line.split()
                if len(parts) >= 4:
                    proto = parts[0]
                    local = parts[1]
                    remote = parts[2] if len(parts) > 2 else "-"
                    state = parts[3] if proto == "TCP" and len(parts) > 3 else "-"
                    pid = parts[-1]
                    connections.add(f"{proto} {local} -> {remote} | {state} | PID: {pid}")
        return connections
    except Exception as e:
        return {f"Error: {e}"}
    
# Continuously monitors network connections and detects changes between snapshots.
def monitor_mode():
    previous = get_connections() # Capture the initial connection list to use as the baseline.
    baseline = True
    try:
        while True:
            clear_screen()
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print("=" * 70)
            print(f" NetHawk 1.2.3 | Live Monitor | {now}")
            print("=" * 70)
            print("Press Ctrl+C to return to menu\n")

            current = get_connections()
            total_connections = len(current)
            unique_pids = set() # Track the number of connections associated with each Windows process ID.
            pid_counts = {}
            for c in current:
                pid = c.split("PID: ")[-1]
                unique_pids.add(pid)
                pid_counts[pid] = pid_counts.get(pid, 0) + 1

            if pid_counts:
                busiest_pid = max(pid_counts, key=pid_counts.get) # Find the process ID associated with the largest number of connections.
                process_name = "Unknown"
                result = run_cmd(f"tasklist /FI \"PID eq {busiest_pid}\" /FO CSV /NH") # Resolve the busiest process ID to its Windows process name.
                if result:
                    parts = result.strip().split(",")
                    if parts:
                        process_name = parts[0].strip('"')

                print(f"Busiest Process: {process_name} (PID {busiest_pid}) - {pid_counts[busiest_pid]} connections")
            print(f"Unique processes: {len(unique_pids)}")

            # Count the different types of network connections in the current snapshot.
            tcp_connections = sum(c.startswith("TCP") for c in current)
            udp_connections = sum(c.startswith("UDP") for c in current)
            established = sum("ESTABLISHED" in c for c in current)
            listening = sum("LISTENING" in c for c in current)
            time_wait = sum("TIME_WAIT" in c for c in current)
            other_tcp = tcp_connections - established - listening - time_wait
            if any(c.startswith("Error") for c in current):
                print("Error getting connections")
                time.sleep(2)
                continue

           # Compares the current snapshot with the previous snapshot
           # Identifies newly created and closed connections.
            new_conns = current - previous 
            closed_conns = previous - current

            if not baseline:
                if new_conns: # Display newly detected network connections.
                    print("[+] NEW:")
                    for c in sorted(new_conns):
                        protocol = c.split()[0]
                        print(f"  [{protocol}]  {c[len(protocol) + 1:]}")
                    print()
                if closed_conns: # Display connections that are no longer present.
                    print("[-] CLOSED:")
                    for c in sorted(closed_conns):
                        protocol = c.split()[0]
                        print(f"  [{protocol}]  {c[len(protocol) + 1:]}")
                    print()
                if not new_conns and not closed_conns:
                    print("No connection changes.\n")
            else:
                baseline = False

            print(f"Total connections: {total_connections}")
            print(f"TCP connections: {tcp_connections}")
            print(f"UDP connections: {udp_connections}")
            print(f"ESTABLISHED: {established}")
            print(f"LISTENING: {listening}")
            print(f"TIME_WAIT: {time_wait}")
            print(f"Other TCP: {other_tcp}")
            previous = current
            time.sleep(2)
    except KeyboardInterrupt:
        pass

# =========================
# MAIN MENU
# =========================

# Displays the main NetHawk menu and launches the selected network tool.
def main():
    log_event(" Beta-C NetHawk 1.2.3 started")
    while True:
        clear_screen()
        print("=" * 70)
        print("Beta-C NetHawk 1.2.3 - Network Toolkit")
        print("=" * 70)
        print("1. Live Connection Monitor")
        print("2. Network Information")
        print("3. Network Diagnostics")
        print("4. Port Scanner")
        print("5. Exit")
        choice = input("\nSelect option: ").strip()

        if choice == "1":
            monitor_mode()
        elif choice == "2":
            show_network_info()
        elif choice == "3":
            diagnostics_menu()
        elif choice == "4":
            port_scan()
        elif choice == "5":
            print("\nGoodbye.")
            log_event("NetHawk 1.2.3 exited")
            break
        else:
            print("Invalid choice.")
            time.sleep(1)

# Start NetHawk only when this file is executed directly.
if __name__ == "__main__":
    main()

