# Traffic Vision — Network Traffic Monitoring and Analysis Platform

**Traffic Vision** is a real-time network traffic monitoring and analysis platform built with Python Flask and Scapy. This system captures live network packets, displays them in a web interface, and provides filtering and statistical analysis capabilities.

## Features

- **Real-Time Packet Capture**: Captures live network traffic using Scapy
- **Protocol Detection**: Identifies TCP, UDP, and ICMP protocols
- **Port-to-Service Mapping**: Maps common port numbers to service names (HTTP, HTTPS, DNS, SSH, etc.)
- **Filtering**: Filter packets by protocol type, source IP, and destination IP
- **Statistics**: View total packets, per-protocol counts, and average packet size
- **System Logs**: Track monitoring start/stop events and errors
- **CSV Export**: Export captured data as a CSV file
- **Interface Selection**: Choose which network interface to monitor

## Prerequisites

1. **Python 3.7+** installed
2. **Npcap** (Windows) — Download from [https://npcap.com/](https://npcap.com/)
   - During installation, select **"WinPcap API-compatible mode"**
3. **Administrator privileges** — Required for packet capture

## Installation

1. Navigate to the project directory:
   ```
   cd ComputerNetworks-Project
   ```

2. Install Python dependencies:
   ```
   pip install -r requirements.txt
   ```

## Running the Application

**Important**: Run as Administrator for packet capture to work.

1. Open Command Prompt or PowerShell **as Administrator**
2. Navigate to the project directory
3. Run:
   ```
   python app.py
   ```
4. Open your browser and go to: **http://127.0.0.1:5000**

## Usage

1. Select a **network interface** from the dropdown menu
2. Click **Start Monitoring** to begin capturing packets
3. Packets will appear in the table, updating every 2 seconds
4. Use the **Filter** panel to filter by protocol, source IP, or destination IP
5. View **Statistics** for packet counts and sizes
6. Click **Stop Monitoring** to stop capturing
7. Click **Export CSV** to download the captured data

## Project Structure

```
ComputerNetworks-Project/
├── app.py                  # Flask backend application
├── sniffer.py              # Scapy packet capture module
├── requirements.txt        # Python dependencies
├── README.md               # This file
├── templates/
│   └── index.html          # Web interface
└── static/
    ├── style.css           # Stylesheet
    └── script.js           # Frontend JavaScript
```

> **Note:** The dataset file is generated from real captured traffic using the **Export CSV** button in the interface. Start monitoring, capture packets, then click Export to save the dataset.

## Technologies Used

- **Backend**: Python, Flask, Scapy
- **Frontend**: HTML, CSS, JavaScript
- **Packet Capture**: Scapy (real-time sniffing)

## Dataset Fields

| Field            | Description                          |
|------------------|--------------------------------------|
| Time             | Timestamp of packet capture          |
| Source IP        | Source IP address                     |
| Destination IP   | Destination IP address               |
| Protocol         | Protocol type (TCP/UDP/ICMP)         |
| Source Port      | Source port number                    |
| Destination Port | Destination port number              |
| Service          | Service name (mapped from port)      |
| Packet Size      | Size of the packet in bytes          |
