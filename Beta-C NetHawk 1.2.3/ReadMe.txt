Beta-C NetHawk 1.2.3

NetHawk is a Windows network monitoring and diagnostics toolkit written in Python.

This project was created as a learning and cybersecurity project to practice Python programming, networking, socket programming, multithreading, Windows networking commands, logging, and network monitoring.

FEATURES
Live network connection monitoring
TCP and UDP connection tracking
NEW and CLOSED connection detection
Network connection statistics
Process and PID tracking
Busiest process identification
Network information
Hostname and local IPv4 detection
IP configuration information
Default route information
Windows network interface information
Ping testing
DNS lookup
TCP connection testing
Traceroute
Threaded TCP port scanning
Common-port scanning
Custom port-range scanning
Timestamped activity logging
REQUIREMENTS
Windows
Python 3.x
Network connection for certain diagnostic functions
RUNNING NETHAWK

You can start NetHawk from the command line with:

python "Beta-C NetHawk 1.2.3.py"

You can also double-click:

Start_NetHawk.bat

The batch file launches NetHawk automatically.

LOGGING

NetHawk creates:

nethawk_log.txt

The log records events such as:

NetHawk startup and shutdown
Ping tests
DNS lookups
TCP tests
Traceroutes
Port scans
PORT SCANNING

NetHawk provides two scanning options:

Common ports
Custom port ranges

The port scanner uses multiple threads to scan ports concurrently.

Only scan systems and networks that you own or have explicit permission to test.

WINDOWS COMMANDS USED

NetHawk uses several built-in Windows networking commands, including:

ipconfig
route
netsh
ping
nslookup
tracert
netstat
tasklist
PROJECT STATUS

Version: Beta-C NetHawk 1.2.3

Status: Beta

Beta-C 1.2.3 is a stable beta checkpoint of the NetHawk project.

Future versions may add new functionality, improvements, and refinements.

PURPOSE

NetHawk is primarily a personal learning and cybersecurity portfolio project.

It is designed to help develop practical Python programming, networking,
and cybersecurity skills.

NetHawk is not intended to replace professional network monitoring or
security software.