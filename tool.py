import logging
import sys
import time
from datetime import datetime
import numpy as np
import pandas as pd
from scapy.all import sniff, IP, TCP, UDP
from scapy.layers.inet import IP, TCP, UDP
import tensorflow as tf
from tensorflow.keras.models import load_model
import queue
import threading
from collections import defaultdict
import os

class NetworkIDS:
    def __init__(self, model_path, log_path="ids_alerts.log"):
        """
        Initialize the IDS with model and logging configuration
        """
        # Setup logging
        self.setup_logging(log_path)
        
        # Load the model
        try:
            self.model = load_model(model_path)
            logging.info("Model loaded successfully")
        except Exception as e:
            logging.error(f"Failed to load model: {str(e)}")
            sys.exit(1)
            
        # Initialize traffic statistics
        self.stats = defaultdict(lambda: defaultdict(int))
        self.packet_queue = queue.Queue(maxsize=1000)
        self.is_running = True
        
        # Time window for feature calculation (in seconds)
        self.time_window = 2
        
        # Start the processing thread
        self.processing_thread = threading.Thread(target=self.process_packet_queue)
        self.processing_thread.daemon = True
        self.processing_thread.start()

    def setup_logging(self, log_path):
        """Configure logging with both file and console output"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_path),
                logging.StreamHandler(sys.stdout)
            ]
        )

    def extract_features(self, packet):
        """
        Extract relevant features from a packet for intrusion detection
        """
        features = {
            'duration': 0,
            'protocol_type': 0,
            'service': 0,
            'flag': 0,
            'src_bytes': 0,
            'dst_bytes': 0,
            'land': 0,
            'wrong_fragment': 0,
            'urgent': 0,
            'hot': 0,
            'num_failed_logins': 0,
            'logged_in': 0,
            'num_compromised': 0,
            'root_shell': 0,
            'su_attempted': 0,
            'num_root': 0,
            'num_file_creations': 0,
            'num_shells': 0,
            'num_access_files': 0,
            'num_outbound_cmds': 0,
            'is_host_login': 0,
            'is_guest_login': 0,
            'count': 0,
            'srv_count': 0,
            'serror_rate': 0,
            'srv_serror_rate': 0,
            'rerror_rate': 0,
            'srv_rerror_rate': 0,
            'same_srv_rate': 0,
            'diff_srv_rate': 0,
            'srv_diff_host_rate': 0,
            'dst_host_count': 0,
            'dst_host_srv_count': 0,
            'dst_host_same_srv_rate': 0,
            'dst_host_diff_srv_rate': 0,
            'dst_host_same_src_port_rate': 0,
            'dst_host_srv_diff_host_rate': 0,
            'dst_host_serror_rate': 0,
            'dst_host_srv_serror_rate': 0,
            'dst_host_rerror_rate': 0,
            'dst_host_srv_rerror_rate': 0
        }

        try:
            if IP in packet:
                # Basic packet info
                features['protocol_type'] = self.get_protocol_number(packet)
                features['src_bytes'] = len(packet)
                features['dst_bytes'] = len(packet.payload)
                
                # Connection features
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                
                # Update connection statistics
                self.stats['connections'][(src_ip, dst_ip)] += 1
                features['count'] = self.stats['connections'][(src_ip, dst_ip)]
                
                if TCP in packet:
                    features['service'] = packet[TCP].dport
                    features['flag'] = packet[TCP].flags
                    features['urgent'] = packet[TCP].flags.U
                    
                # Calculate rates and ratios
                total_connections = sum(self.stats['connections'].values())
                if total_connections > 0:
                    features['same_srv_rate'] = self.stats['connections'][(src_ip, dst_ip)] / total_connections
                
                # Check for suspicious patterns
                if features['urgent'] and features['count'] > 10:
                    features['hot'] = 1
                    
        except Exception as e:
            logging.error(f"Error extracting features: {str(e)}")
            return None
            
        return list(features.values())

    def get_protocol_number(self, packet):
        """Convert protocol to number for model input"""
        if TCP in packet:
            return 6
        elif UDP in packet:
            return 17
        return 0

    def packet_callback(self, packet):
        """Callback function for packet processing"""
        try:
            if IP in packet:
                self.packet_queue.put(packet)
        except Exception as e:
            logging.error(f"Error in packet callback: {str(e)}")

    def process_packet_queue(self):
        """Process packets from the queue"""
        while self.is_running:
            try:
                packet = self.packet_queue.get(timeout=1)
                features = self.extract_features(packet)
                
                if features:
                    features_array = np.array(features).reshape(1, -1)
                    prediction = self.model.predict(features_array)
                    
                    if prediction[0][0] < 0.5:  # Threshold for anomaly detection
                        self.alert(packet, prediction[0][0])
                        
            except queue.Empty:
                continue
            except Exception as e:
                logging.error(f"Error processing packet: {str(e)}")

    def alert(self, packet, confidence):
        """Generate alert for suspicious activity"""
        try:
            if IP in packet:
                alert_msg = (
                    f"ALERT: Potential intrusion detected\n"
                    f"Source IP: {packet[IP].src}\n"
                    f"Destination IP: {packet[IP].dst}\n"
                    f"Confidence: {(1 - confidence) * 100:.2f}%\n"
                    f"Timestamp: {datetime.now()}\n"
                )
                logging.warning(alert_msg)
                
                # Save packet details for forensics
                if not os.path.exists('suspicious_packets'):
                    os.makedirs('suspicious_packets')
                    
                filename = f"suspicious_packets/packet_{int(time.time())}.pcap"
                packet.write(filename)
                
        except Exception as e:
            logging.error(f"Error generating alert: {str(e)}")

    def start(self):
        """Start the IDS"""
        logging.info("Starting Network IDS...")
        try:
            sniff(prn=self.packet_callback, store=False)
        except KeyboardInterrupt:
            logging.info("Stopping Network IDS...")
            self.stop()
        except Exception as e:
            logging.error(f"Error in packet capture: {str(e)}")
            self.stop()

    def stop(self):
        """Stop the IDS gracefully"""
        self.is_running = False
        if self.processing_thread.is_alive():
            self.processing_thread.join()
        logging.info("IDS stopped successfully")

def main():
    """Main function to run the IDS"""
    # Check for root/admin privileges
    if os.geteuid() != 0:
        print("This program requires root privileges to capture packets.")
        sys.exit(1)
        
    model_path = './network_intrusion_detection.h5'
    ids = NetworkIDS(model_path)
    
    try:
        ids.start()
    except KeyboardInterrupt:
        ids.stop()

if __name__ == "__main__":
    main()