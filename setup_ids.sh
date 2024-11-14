#!/bin/bash

# setup_ids.sh
# Make the script executable with: chmod +x setup_ids.sh

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root"
    exit 1
fi

# Create directory structure
echo "Creating directory structure..."
mkdir -p /opt/network_ids
mkdir -p /var/log/network_ids
mkdir -p /opt/network_ids/suspicious_packets

# Install required packages
echo "Installing required packages..."
apt-get update
apt-get install -y python3-pip python3-venv tcpdump

# Create virtual environment
echo "Setting up Python virtual environment..."
python3 -m venv /opt/network_ids/venv
source /opt/network_ids/venv/bin/activate

# Install Python dependencies
echo "Installing Python dependencies..."
pip install tensorflow numpy pandas scapy

# Copy IDS script
echo "Installing IDS script..."
cat > /opt/network_ids/ids.py << 'EOL'
# Your entire IDS code goes here
# Copy the entire content of the previous Python script here
EOL

# Create start script
echo "Creating start script..."
cat > /opt/network_ids/start_ids.sh << 'EOL'
#!/bin/bash
source /opt/network_ids/venv/bin/activate
python3 /opt/network_ids/ids.py
EOL

# Make start script executable
chmod +x /opt/network_ids/start_ids.sh

# Create systemd service file
echo "Creating systemd service..."
cat > /etc/systemd/system/network-ids.service << 'EOL'
[Unit]
Description=Network Intrusion Detection System
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/network_ids
ExecStart=/opt/network_ids/start_ids.sh
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOL

# Set permissions
echo "Setting permissions..."
chmod 644 /etc/systemd/system/network-ids.service
chmod -R 750 /opt/network_ids
chmod -R 750 /var/log/network_ids

# Reload systemd
echo "Reloading systemd..."
systemctl daemon-reload

echo "Setup complete!"
echo "To start the IDS service, run: systemctl start network-ids"
echo "To enable IDS on boot, run: systemctl enable network-ids"
echo "To check status, run: systemctl status network-ids"
echo "View logs with: tail -f /var/log/network_ids/ids_alerts.log"