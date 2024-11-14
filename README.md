# Network Intrusion Detection System (NIDS) Setup Guide

This guide walks you through setting up a Network Intrusion Detection System (NIDS) using a Python script with TensorFlow and Scapy. The system monitors network traffic for potential intrusions by capturing packets, extracting features, and analyzing them with a pre-trained model.

---

### Index
1. [Prerequisites](#prerequisites)
2. [Installation Process](#installation-process)
   - [Clone the Repository](#1-clone-the-repository)
   - [Make the Setup Script Executable](#2-make-the-setup-script-executable)
   - [Run the Setup Script](#3-run-the-setup-script)
3. [Setup Breakdown](#setup-breakdown)
4. [Usage](#usage)
5. [Troubleshooting](#troubleshooting)

---

### Prerequisites
- **Root privileges**: Required to capture network packets.
- **TensorFlow model file**: `.h5` file trained for anomaly detection.
- **Operating system**: Ubuntu/Debian-based environment is recommended.

---

### Installation Process

#### 1. Clone the Repository
Clone the repository to your system:
```bash
git clone https://github.com/yourusername/network-ids.git
cd network-ids
```

#### 2. Make the Setup Script Executable
Before running the setup script, make it executable:
```bash
chmod +x setup_ids.sh
```

#### 3. Run the Setup Script
Run the setup script as root:
```bash
sudo ./setup_ids.sh
```

The setup script performs the following tasks:
- Creates directories for logs and script storage.
- Installs required packages (Python, pip, virtual environment, and tcpdump).
- Sets up a virtual environment and installs necessary Python dependencies.
- Copies the IDS Python script (`ids.py`) to the designated directory.
- Creates a systemd service file to manage the IDS as a service.

---

### Setup Breakdown

1. **Directory Structure**  
   The setup script creates directories:
   - `/opt/network_ids`: Contains the IDS script, virtual environment, and other configuration files.
   - `/var/log/network_ids`: Stores logs for detected intrusions.
   - `/opt/network_ids/suspicious_packets`: For saving packet captures flagged as suspicious.

2. **Install Required Packages**  
   Installs `python3-pip`, `python3-venv`, and `tcpdump`, which are essential for the NIDS functionality.

3. **Python Virtual Environment**  
   Sets up a virtual environment in `/opt/network_ids/venv` and installs Python dependencies (TensorFlow, Scapy, NumPy, and Pandas) inside it.

4. **Install IDS Script**  
   Copies the main IDS Python script (`ids.py`) into `/opt/network_ids`. This script should include code for capturing network packets, extracting features, and detecting anomalies using the pre-trained model.

5. **Start Script**  
   Creates a `start_ids.sh` script to activate the virtual environment and execute the IDS script for easy startup.

6. **Systemd Service**  
   A `systemd` service file (`network-ids.service`) is created to allow starting, stopping, and enabling the IDS as a background service, which starts automatically at boot and restarts if it stops unexpectedly.

7. **Permissions and Finalization**  
   Sets appropriate permissions on files and directories, reloads `systemd`, and provides instructions for managing the service.

---

### Usage

- **Start the IDS**  
  ```bash
  sudo systemctl start network-ids
  ```

- **Enable on Boot**  
  ```bash
  sudo systemctl enable network-ids
  ```

- **Check Status**  
  ```bash
  sudo systemctl status network-ids
  ```

- **View Logs**  
  ```bash
  tail -f /var/log/network_ids/ids_alerts.log
  ```

---

### Troubleshooting

- **Service Not Starting**: Ensure the script was run as root and `systemd` was reloaded. Check permissions on `/opt/network_ids` and `/var/log/network_ids`.
- **Logs Not Updating**: Verify the IDS script is functioning and capturing packets. Check if the correct network interface is used in the IDS script.

This setup provides a foundational NIDS capable of real-time detection, logging, and management through `systemd`.