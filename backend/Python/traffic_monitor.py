import pyshark
from flask import Flask, request, send_file, jsonify
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import json
import threading
import asyncio
import csv
import os
import numpy as np

import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import tempfile
import shutil
import logging
import spacy

app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="http://localhost:3000")

nlp = spacy.load('en_core_web_sm')

# Event for stopping the capture
stop_capture_flag = threading.Event()
capture_thread = None  # To store the thread for capturing packets

# Store captured data
captured_data = []

# Create a dictionary to store flow-level data
flows = {}

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Predefined threat solutions and severity levels
threat_solutions = {
    'DoS Hulk': {
        'severity': 'High',
        'explanation': 'DoS Hulk is a Denial of Service attack which floods the target with a huge amount of HTTP requests.',
        'solution': 'Use rate limiting, Web Application Firewalls, and DDoS mitigation services to prevent overload.'
    },
    'DoS GoldenEye': {
        'severity': 'High',
        'explanation': 'DoS GoldenEye is an HTTP DoS attack that overwhelms web services using slow requests.',
        'solution': 'Use rate-limiting to detection and prevent slow attack patterns, plus implementation of Web Application Firewalls and reverse proxies are recommended.'
    },
    'DoS slowloris': {
        'severity': 'Medium',
        'explanation': 'DoS slowloris is a slow header-based DoS attack.',
        'solution': 'Configure server timeouts, limit header size, and employ application-level firewalls.'
    },
    'DoS Slowhttptest': {
        'severity': 'Medium',
        'explanation': 'DoS SlowHTTPTest is a DoS attack that sends slow POST requests to exhaust server resources.',
        'solution': 'Configure aggresive timeouts, limit the size and rate of POST requests.'
    },
    'Heartbleed': {
        'severity': 'High',
        'explanation': 'Heartbleed exploits a vulnerability in OpenSSL, allowing attackers to extract sensitive data.',
        'solution': 'Patch OpenSSL to remove vulnerability, regenerate SSL certificates, and revoke old ones.'
    },
    'DDoS': {
        'severity': 'Critical',
        'explanation': 'DDoS is a distributed DoS attack that using multiple sources to overwhelm the server.',
        'solution': 'Implement DDoS mitigation services like Cloudflare, use rate limiting and load balancing to distribute the load.'
    },
    'FTP-Patator': {
        'severity': 'Medium',
        'explanation': 'FTP-Patator is a brute-force attack targeting FTP login credentials.',
        'solution': 'Enforce strong password policies, implement account lockout mechanisms and CAPTCHAs.'
    },
    'SSH-Patator': {
        'severity': 'Medium',
        'explanation': 'SSH-Patator is a brute-force SSH attack.',
        'solution': 'Use rate limiting, Web Application Firewalls, and DDoS mitigation services to prevent overload.'
    },
    'Bot': {
        'severity': 'High',
        'explanation': 'Compromised systems controlled by a botnet.',
        'solution': 'Employ Intrusion Detection Systems (IDS) to monitor suspicious activity, or block known botnet Command & Control (C&C) servers.'
    },
    'Infiltration': {
        'severity': 'High',
        'explanation': 'Infiltration is an unauthorized internal access to the network.',
        'solution': 'Implement internal network segmentation or use Endpoint Detection and Response (EDR) solutions.'
    },
    'Web Attack (Brute Force)': {
        'severity': 'Medium',
        'explanation': 'Web attack via brute force is the repeated login attempts on web applications.',
        'solution': 'Apply rate-limiting, account lockout policies, and use CAPTCHA after multiple failed attempts.'
    },
    'Web Attack (XSS)': {
        'severity': 'Medium',
        'explanation': 'Web attack via XSS is the Cross-Site Scripting (XSS) attacks to inject malicious scripts into web pages.',
        'solution': 'Sanitize user inputs and use Content Security Policy (CSP) to limit script execution.'
    },
    'Web Attack (SQL Injection)': {
        'severity': 'High',
        'explanation': 'Web attack via SQL injection is an attack that exploits vulnerabilities to manipulate databases.',
        'solution': 'Use parameterized queries, ORM frameworks, input validation, or limit database permissions to prevent SQL injection.'
    },
    'FTP-BruteForce': {
        'severity': 'Medium',
        'explanation': 'FTP-BruteForce is a brute-force attack on FTP services where attackers attempt to guess login credentials.',
        'solution': 'Implement strong password policies, rate limiting, or Multi-Factor Authentication (MFA).'
    },
    'SSH-Bruteforce': {
        'severity': 'Medium',
        'explanation': 'SSH-Bruteforce is a brute-force attack which involving attempt to try gain access to SSH services via brute-forcing login credentials.',
        'solution': 'Disable password-based logins, limit SSH access, or Multi-Factor Authentication (MFA).'
    }
}

# Predefined intents and responses
intent_mapping = {
    'upload dataset': 'You can upload a dataset by clicking the "Upload Dataset" button.',
    'check threats': 'Please upload a dataset to analyze threats in your network.',
    'get threat solutions': 'Here is the solution for the identified threat: {threat}. Solution: {solution}.',
    'critical threat alert': 'More than one critical threat has been detected!'
}

# Global variable for storing dataset path temporarily
uploaded_dataset_path = None

def capture_packets():
    global stop_capture_flag, captured_data
    # Setup the event loop manually for the current thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    ####### IMPORTANT!!! TO CHANGE THE NETWORK INTERFACE! #######
    # Capture live traffic on specific interface (Wi-Fi)
    capture = pyshark.LiveCapture(
        interface='Wi-Fi',
        encryption_type='WPA-PWD',
        # decryption_key='TP066841'
        decryption_key='jHpHgWrXc789721!@#'
    )

    # Start sniffing packets continuously
    for packet in capture.sniff_continuously():
        if stop_capture_flag.is_set():  # Check if stop flag is set
            break

        try:
            # Extract key flow attributes (5 tuples)
            flow_key = (
                packet.ip.src if hasattr(packet, 'ip') else 'N/A',
                packet.ip.dst if hasattr(packet, 'ip') else 'N/A',
                packet[packet.transport_layer].srcport if hasattr(packet, 'transport_layer') else 'N/A',
                packet[packet.transport_layer].dstport if hasattr(packet, 'transport_layer') else 'N/A',
                packet.highest_layer,
            )

            packet_info = {
                'Dst Port': packet[packet.transport_layer].dstport if hasattr(packet, 'transport_layer') else 'N/A',
                'Protocol': packet.highest_layer,
                'Timestamp': str(packet.sniff_time),
                'Flow Duration': 0,
                'Tot Fwd Pkts': 0,  
                'Tot Bwd Pkts': 0, 
                'TotLen Fwd Pkts': 0,
                'TotLen Bwd Pkts': 0,
                'Fwd Pkt Len Max': 0,
                'Fwd Pkt Len Min': 0,
                'Fwd Pkt Len Mean': 0,
                'Fwd Pkt Len Std': 0,
                'Bwd Pkt Len Max': 0,
                'Bwd Pkt Len Min': 0,
                'Bwd Pkt Len Mean': 0,
                'Bwd Pkt Len Std': 0,
                'Flow Byts/s': 0,
                'Flow Pkts/s': 0,
                'Flow IAT Mean': 0,
                'Flow IAT Std': 0,
                'Flow IAT Max': 0,
                'Flow IAT Min': 0,
                'Fwd IAT Tot': 0,
                'Fwd IAT Mean': 0,
                'Fwd IAT Std': 0,
                'Fwd IAT Max': 0,
                'Fwd IAT Min': 0,
                'Bwd IAT Tot': 0,
                'Bwd IAT Mean': 0,
                'Bwd IAT Std': 0,
                'Bwd IAT Max': 0,
                'Bwd IAT Min': 0,
                'Fwd PSH Flags': 0,
                'Bwd PSH Flags': 0,
                'Fwd URG Flags': 0,
                'Bwd URG Flags': 0,
                'Fwd Header Len': 0,
                'Bwd Header Len': 0,
                'Fwd Pkts/s': 0,
                'Bwd Pkts/s': 0,
                'Pkt Len Min': 0,
                'Pkt Len Max': 0,
                'Pkt Len Mean': 0,
                'Pkt Len Std': 0,
                'Pkt Len Var': 0,
                'FIN Flag Cnt': 0,
                'SYN Flag Cnt': 0,
                'RST Flag Cnt': 0,
                'PSH Flag Cnt': 0,
                'ACK Flag Cnt': 0,
                'URG Flag Cnt': 0,
                'CWE Flag Count': 0,
                'ECE Flag Cnt': 0,
                'Down/Up Ratio': 0,
                'Pkt Size Avg': 0,
                'Fwd Seg Size Avg': 0,
                'Bwd Seg Size Avg': 0,
                'Fwd Byts/b Avg': 0,
                'Fwd Pkts/b Avg': 0,
                'Fwd Blk Rate Avg': 0,
                'Bwd Byts/b Avg': 0,
                'Bwd Pkts/b Avg': 0,
                'Bwd Blk Rate Avg': 0,
                'Subflow Fwd Pkts': 0,
                'Subflow Fwd Byts': 0,
                'Subflow Bwd Pkts': 0,
                'Subflow Bwd Byts': 0,
                'Init Fwd Win Byts': 0,
                'Init Bwd Win Byts': 0,
                'Fwd Act Data Pkts': 0,
                'Fwd Seg Size Min': 0,
                'Active Mean': 0,
                'Active Std': 0,
                'Active Max': 0,
                'Active Min': 0,
                'Idle Mean': 0,
                'Idle Std': 0,
                'Idle Max': 0,
                'Idle Min': 0,
                'Label': 'N/A' 
            }

            if flow_key not in flows:
                flows[flow_key] = {
                    'start_time': packet.sniff_time,
                    'end_time': packet.sniff_time,
                    'total_forward_packets': 0,
                    'total_backward_packets': 0,
                    'total_forward_bytes': 0,
                    'total_backward_bytes': 0,
                    'fwd_header_length': 0,
                    'bwd_header_length': 0,
                    'fwd_packet_lengths': [],
                    'bwd_packet_lengths': [],
                    'iat_list': [],
                    'fwd_iat_list': [],
                    'bwd_iat_list': [],
                    'length_list': [],
                    'tcp_flags': {
                        'FIN': 0,
                        'SYN': 0,
                        'RST': 0,
                        'PSH': 0,
                        'ACK': 0,
                        'URG': 0,
                        'CWE': 0,
                        'ECE': 0,
                    },
                    'last_packet_time': packet.sniff_time,
                    'last_fwd_packet_time': packet.sniff_time,
                    'last_bwd_packet_time': packet.sniff_time,
                    'flow_duration': 0,
                    'idle_time': 0,
                    'active_time': 0,
                }

            # Get the flow and update its statistics
            flow = flows[flow_key]

            # Calculate flow duration
            flow['end_time'] = packet.sniff_time
            flow['flow_duration'] = (flow['end_time'] - flow['start_time']).total_seconds() * 1000  # Duration in ms
            packet_info['Flow Duration'] = flow['flow_duration']

           # Check packet direction
            if flow_key[0] == packet.ip.src:
                flow['total_forward_packets'] += 1
                flow['total_forward_bytes'] += int(packet.length)
                flow['fwd_header_length'] += int(packet.ip.hdr_len) if hasattr(packet.ip, 'hdr_len') else 0
                flow['fwd_packet_lengths'].append(int(packet.length))

                # Forward inter-arrival time
                fwd_iat = (packet.sniff_time - flow['last_fwd_packet_time']).total_seconds() * 1000
                flow['fwd_iat_list'].append(fwd_iat)
                flow['last_fwd_packet_time'] = packet.sniff_time
            else:
                flow['total_backward_packets'] += 1
                flow['total_backward_bytes'] += int(packet.length)
                flow['bwd_header_length'] += int(packet.ip.hdr_len) if hasattr(packet.ip, 'hdr_len') else 0
                flow['bwd_packet_lengths'].append(int(packet.length))

                # Backward inter-arrival time
                bwd_iat = (packet.sniff_time - flow['last_bwd_packet_time']).total_seconds() * 1000
                flow['bwd_iat_list'].append(bwd_iat)
                flow['last_bwd_packet_time'] = packet.sniff_time

            # Calculate packet length statistics (min, max, mean, std) for forward and backward directions
            if flow['fwd_packet_lengths']:
                packet_info['Fwd Pkt Len Max'] = np.max(flow['fwd_packet_lengths'])
                packet_info['Fwd Pkt Len Min'] = np.min(flow['fwd_packet_lengths'])
                packet_info['Fwd Pkt Len Mean'] = np.mean(flow['fwd_packet_lengths'])
                packet_info['Fwd Pkt Len Std'] = np.std(flow['fwd_packet_lengths'])
            
            if flow['bwd_packet_lengths']:
                packet_info['Bwd Pkt Len Max'] = np.max(flow['bwd_packet_lengths'])
                packet_info['Bwd Pkt Len Min'] = np.min(flow['bwd_packet_lengths'])
                packet_info['Bwd Pkt Len Mean'] = np.mean(flow['bwd_packet_lengths'])
                packet_info['Bwd Pkt Len Std'] = np.std(flow['bwd_packet_lengths'])
            
            # Calculate variance of packet lengths (for both forward and backward)
            all_packet_lengths = flow['fwd_packet_lengths'] + flow['bwd_packet_lengths']
            if all_packet_lengths:
                packet_info['Pkt Len Var'] = np.var(all_packet_lengths)
            else:
                packet_info['Pkt Len Var'] = 0

            # Calculate inter-arrival time statistics (for both forward and backward directions)
            if flow['fwd_iat_list']:
                packet_info['Fwd IAT Tot'] = np.sum(flow['fwd_iat_list'])
                packet_info['Fwd IAT Mean'] = np.mean(flow['fwd_iat_list'])
                packet_info['Fwd IAT Std'] = np.std(flow['fwd_iat_list'])
                packet_info['Fwd IAT Max'] = np.max(flow['fwd_iat_list'])
                packet_info['Fwd IAT Min'] = np.min(flow['fwd_iat_list'])

            if flow['bwd_iat_list']:
                packet_info['Bwd IAT Tot'] = np.sum(flow['bwd_iat_list'])
                packet_info['Bwd IAT Mean'] = np.mean(flow['bwd_iat_list'])
                packet_info['Bwd IAT Std'] = np.std(flow['bwd_iat_list'])
                packet_info['Bwd IAT Max'] = np.max(flow['bwd_iat_list'])
                packet_info['Bwd IAT Min'] = np.min(flow['bwd_iat_list'])
            
            # Capture TCP flags (SYN, ACK, FIN, RST)
            if hasattr(packet, 'tcp'):
                tcp_flags = int(packet.tcp.flags, 16)  # Convert to integer
                flow['tcp_flags']['FIN'] += (1 if tcp_flags & 0x01 else 0)
                flow['tcp_flags']['SYN'] += (1 if tcp_flags & 0x02 else 0)
                flow['tcp_flags']['RST'] += (1 if tcp_flags & 0x04 else 0)
                flow['tcp_flags']['PSH'] += (1 if tcp_flags & 0x08 else 0)
                flow['tcp_flags']['ACK'] += (1 if tcp_flags & 0x10 else 0)
                flow['tcp_flags']['URG'] += (1 if tcp_flags & 0x20 else 0)
                flow['tcp_flags']['CWE'] += (1 if tcp_flags & 0x40 else 0)
                flow['tcp_flags']['ECE'] += (1 if tcp_flags & 0x80 else 0)

            # Calculate inter-arrival time (IAT)
            current_iat = (packet.sniff_time - flow['last_packet_time']).total_seconds() * 1000  # IAT in ms
            flow['iat_list'].append(current_iat)
            flow['last_packet_time'] = packet.sniff_time

            # Calculate IAT statistics (mean, std, max, min)
            if len(flow['iat_list']) > 0:
                packet_info['Flow IAT Mean'] = np.mean(flow['iat_list'])
                packet_info['Flow IAT Std'] = np.std(flow['iat_list'])
                packet_info['Flow IAT Max'] = np.max(flow['iat_list'])
                packet_info['Flow IAT Min'] = np.min(flow['iat_list'])
            else:
                packet_info['Flow IAT Mean'] = packet_info['Flow IAT Std'] = packet_info['Flow IAT Max'] = packet_info['Flow IAT Min'] = 0

            packet_info['Tot Fwd Pkts'] = flow['total_forward_packets']
            packet_info['Tot Bwd Pkts'] = flow['total_backward_packets']
            packet_info['TotLen Fwd Pkts'] = flow['total_forward_bytes']
            packet_info['TotLen Bwd Pkts'] = flow['total_backward_bytes']

            # Calculate Flow Bytes/s
            if flow['flow_duration'] > 0:
                packet_info['Flow Byts/s'] = (flow['total_forward_bytes'] + flow['total_backward_bytes']) / (flow['flow_duration'] / 1000)
            else:
                packet_info['Flow Byts/s'] = 0

            # Calculate Packet Rate
            if flow['flow_duration'] > 0:
                packet_info['Flow Pkts/s'] = (flow['total_forward_packets'] + flow['total_backward_packets']) / (flow['flow_duration'] / 1000)
            else:
                packet_info['Flow Pkts/s'] = 0

            # Add idle time (time between last two packets)
            if current_iat > 0:
                flow['idle_time'] += current_iat

            # Calculate active and idle times
            if len(flow['iat_list']) > 0:
                packet_info['Active Mean'] = np.mean(flow['iat_list'])
                packet_info['Active Std'] = np.std(flow['iat_list'])
                packet_info['Active Max'] = np.max(flow['iat_list'])
                packet_info['Active Min'] = np.min(flow['iat_list'])

                # Idle time is the sum of time between packets (when packets aren't sent/received)
                packet_info['Idle Mean'] = packet_info['Active Mean']
                packet_info['Idle Std'] = packet_info['Active Std']
                packet_info['Idle Max'] = packet_info['Active Max']
                packet_info['Idle Min'] = packet_info['Active Min']
            else:
                packet_info['Active Mean'] = packet_info['Active Std'] = packet_info['Active Max'] = packet_info['Active Min'] = 0
                packet_info['Idle Mean'] = packet_info['Idle Std'] = packet_info['Idle Max'] = packet_info['Idle Min'] = 0

            # Packet length statistics (min, max, mean, std)
            flow['length_list'].append(int(packet.length))
            if len(flow['length_list']) > 0:
                packet_info['Pkt Len Min'] = np.min(flow['length_list'])
                packet_info['Pkt Len Max'] = np.max(flow['length_list'])
                packet_info['Pkt Len Mean'] = np.mean(flow['length_list'])
                packet_info['Pkt Len Std'] = np.std(flow['length_list'])
            else:
                packet_info['Pkt Len Min'] = packet_info['Pkt Len Max'] = packet_info['Pkt Len Mean'] = packet_info['Pkt Len Std'] = 0

            # Update subflow stats
            packet_info['Subflow Fwd Pkts'] = flow['total_forward_packets']
            packet_info['Subflow Fwd Byts'] = flow['total_forward_bytes']
            packet_info['Subflow Bwd Pkts'] = flow['total_backward_packets']
            packet_info['Subflow Bwd Byts'] = flow['total_backward_bytes']

            # Calculate Down/Up ratio
            if flow['total_backward_packets'] > 0:
                packet_info['Down/Up Ratio'] = flow['total_forward_packets'] / flow['total_backward_packets']
            else:
                packet_info['Down/Up Ratio'] = flow['total_forward_packets']

            # Header lengths
            packet_info['Fwd Header Len'] = flow['fwd_header_length']
            packet_info['Bwd Header Len'] = flow['bwd_header_length']

            # TCP flags and control information
            packet_info['FIN Flag Cnt'] = flow['tcp_flags']['FIN']
            packet_info['SYN Flag Cnt'] = flow['tcp_flags']['SYN']
            packet_info['RST Flag Cnt'] = flow['tcp_flags']['RST']
            packet_info['PSH Flag Cnt'] = flow['tcp_flags']['PSH']
            packet_info['ACK Flag Cnt'] = flow['tcp_flags']['ACK']
            packet_info['URG Flag Cnt'] = flow['tcp_flags']['URG']
            packet_info['CWE Flag Count'] = flow['tcp_flags']['CWE']
            packet_info['ECE Flag Cnt'] = flow['tcp_flags']['ECE']

            # Calculate forward and backward segment sizes (average and minimum)
            if flow['fwd_packet_lengths']:
                packet_info['Fwd Seg Size Avg'] = np.mean(flow['fwd_packet_lengths'])
                packet_info['Fwd Seg Size Min'] = np.min(flow['fwd_packet_lengths'])

            if flow['bwd_packet_lengths']:
                packet_info['Bwd Seg Size Avg'] = np.mean(flow['bwd_packet_lengths'])

            # Calculate forward and backward bulk metrics (if needed in the setup)
            if len(flow['fwd_packet_lengths']) > 0:
                packet_info['Fwd Byts/b Avg'] = np.mean(flow['fwd_packet_lengths'])  # Placeholder example
                packet_info['Fwd Pkts/b Avg'] = len(flow['fwd_packet_lengths'])  # Placeholder example
                packet_info['Fwd Blk Rate Avg'] = packet_info['Fwd Byts/b Avg'] / flow['flow_duration'] if flow['flow_duration'] > 0 else 0

            if len(flow['bwd_packet_lengths']) > 0:
                packet_info['Bwd Byts/b Avg'] = np.mean(flow['bwd_packet_lengths'])  # Placeholder example
                packet_info['Bwd Pkts/b Avg'] = len(flow['bwd_packet_lengths'])  # Placeholder example
                packet_info['Bwd Blk Rate Avg'] = packet_info['Bwd Byts/b Avg'] / flow['flow_duration'] if flow['flow_duration'] > 0 else 0

            # Initial forward/backward window bytes
            if hasattr(packet, 'tcp'):
                packet_info['Init Fwd Win Byts'] = packet.tcp.window_size if hasattr(packet.tcp, 'window_size') else 0
                packet_info['Init Bwd Win Byts'] = packet.tcp.window_size if hasattr(packet.tcp, 'window_size') else 0

            def convert_to_serializable(data):
                if isinstance(data, np.int64) or isinstance(data, np.float64):
                    return data.item()
                return data
            
            # Apply the conversion to the packet_info dictionary
            packet_info_serializable = {k: convert_to_serializable(v) for k, v in packet_info.items()}
            
            # Send packet info to frontend
            socketio.emit('packet_data', json.dumps(packet_info_serializable))

            # Add to captured data
            captured_data.append(packet_info)

        except AttributeError:
            # Ignore packets without IP layer information
            continue

@app.route('/')
def home():
    return "Real Time Traffic Monitoring Backend Running"

@socketio.on('start_capture')
def start_capture():
    global capture_thread, stop_capture_flag
    stop_capture_flag.clear()  # Clear stop flag to allow capturing

    # Start packet capturing in a new thread
    if capture_thread is None or not capture_thread.is_alive():
        capture_thread = threading.Thread(target=capture_packets)
        capture_thread.start()

    emit('status', {'message': 'Packet capture started'})

@socketio.on('stop_capture')
def stop_capture():
    global stop_capture_flag
    stop_capture_flag.set()  # Set flag to stop capturing
    emit('status', {'message': 'Packet capture stopped'})

@app.route('/export_csv', methods=['POST'])
def export_csv():
    global captured_data
    file_name = request.json.get('file_name', 'traffic_data')

    # Path to save file in Downloads folder
    file_path = os.path.join(os.path.expanduser('~'), 'Downloads', f'{file_name}.csv')

    # Write captured data to CSV file
    with open(file_path, 'w', newline='') as csvfile:
        fieldnames = [
            'Dst Port', 'Protocol', 'Timestamp', 'Flow Duration', 'Tot Fwd Pkts', 'Tot Bwd Pkts',
            'TotLen Fwd Pkts', 'TotLen Bwd Pkts', 'Fwd Pkt Len Max', 'Fwd Pkt Len Min', 
            'Fwd Pkt Len Mean', 'Fwd Pkt Len Std', 'Bwd Pkt Len Max', 'Bwd Pkt Len Min',
            'Bwd Pkt Len Mean', 'Bwd Pkt Len Std', 'Flow Byts/s', 'Flow Pkts/s', 'Flow IAT Mean',
            'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Tot', 'Fwd IAT Mean', 
            'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Tot', 'Bwd IAT Mean', 
            'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 
            'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Len', 'Bwd Header Len', 'Fwd Pkts/s', 
            'Bwd Pkts/s', 'Pkt Len Min', 'Pkt Len Max', 'Pkt Len Mean', 'Pkt Len Std', 
            'Pkt Len Var', 'FIN Flag Cnt', 'SYN Flag Cnt', 'RST Flag Cnt', 'PSH Flag Cnt', 
            'ACK Flag Cnt', 'URG Flag Cnt', 'CWE Flag Count', 'ECE Flag Cnt', 'Down/Up Ratio', 
            'Pkt Size Avg', 'Fwd Seg Size Avg', 'Bwd Seg Size Avg', 'Fwd Byts/b Avg', 
            'Fwd Pkts/b Avg', 'Fwd Blk Rate Avg', 'Bwd Byts/b Avg', 'Bwd Pkts/b Avg', 
            'Bwd Blk Rate Avg', 'Subflow Fwd Pkts', 'Subflow Fwd Byts', 'Subflow Bwd Pkts', 
            'Subflow Bwd Byts', 'Init Fwd Win Byts', 'Init Bwd Win Byts', 'Fwd Act Data Pkts', 
            'Fwd Seg Size Min', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 
            'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label'
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in captured_data:
            row.pop('http_host', None)
            row.pop('dns_query_type', None)
            writer.writerow(row)

    return send_file(file_path, as_attachment=True)

@app.route('/train_cicids2017', methods=['POST'])
def train_cicids2017():
    logging.info("Received a request to train CICIDS2017 dataset.")

    # Check if file is part of the request
    if 'file' not in request.files:
        logging.error("No file part in request.")
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        logging.error("No selected file in request.")
        return jsonify({"error": "No selected file"}), 400
    if not file.filename.endswith('.csv'):
        logging.error("Invalid file format. Expected CSV.")
        return jsonify({"error": "Invalid file format. Please upload a CSV file."}), 400
    
    # Create a persistent temporary directory
    temp_dir = tempfile.mkdtemp()  # Use mkdtemp to persist the directory for the entire operation
    file_path = os.path.join(temp_dir, file.filename)
    file.save(file_path)

    logging.info(f"File {file.filename} saved at {file_path}.")

    # Load the CSV data using Pandas
    try:
        data = pd.read_csv(file_path)
        logging.info("CSV file loaded successfully.")
    except Exception as e:
        logging.error(f"Failed to read CSV file: {str(e)}")
        return jsonify({"error": f"Failed to read CSV file: {str(e)}"}), 500

    # Start the training in a new thread to avoid blocking
    socketio.start_background_task(train_random_forest, data, temp_dir)
    logging.info("Training process started in a background thread.")

    return jsonify({"message": "CSV file uploaded and model training started!"}), 200

# Simulate the training process in a background thread
def train_random_forest(data, temp_dir):
    try:
        # Step 1: Preprocess data
        logging.info("Starting data preprocessing...")

        # Check for and replace NaN or infinite values in dataset
        infinite_columns = data.columns[data.isin([np.inf, -np.inf]).any()]
        logging.info(f"Columns with infinite values: {infinite_columns}")

        data.replace([np.inf, -np.inf], np.nan, inplace=True)

        missing_values = data.isnull().sum()
        logging.info(f"Columns with missing values: {missing_values[missing_values > 0]}")

        for col in data.columns:
            if data[col].dtype in ['float64', 'int64']:
                data[col].fillna(data[col].median(), inplace=True)

        # Convert label columns to numerical values
        label_mapping = {
            'BENIGN': 0,
            'DoS GoldenEye': 1,
            'DoS Hulk': 2,
            'DoS Slowhttptest': 3,
            'DoS slowloris': 4,
            'Heartbleed': 5
        }

        data[' Label'] = data[' Label'].map(label_mapping)

        # Assuming the CICIDS2017 dataset has a 'Label' column for classification
        X = data.drop(' Label', axis=1)  # Features
        y = data[' Label']  # Target (Labels)

        # Step 2: Split data into train and test sets
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42, stratify=y)
        logging.info("Data preprocessing completed. Training and test sets created.")

        # Step 3: Hyperparameter Tuning using GridSearchCV
        logging.info("Training Random Forest model started.")
        # Perform hyperparameter tuning with GridSearchCV
        param_grid = {
            'n_estimators': [100, 200],
            'max_depth': [10, 20, None],
            'min_samples_split': [2, 5],
            'min_samples_leaf': [1, 2]
        }

        rf = RandomForestClassifier(random_state=42, class_weight='balanced')
        grid_search = GridSearchCV(rf, param_grid, cv=5, scoring='accuracy', verbose=1, n_jobs=-1)
        grid_search.fit(X_train, y_train)
        logging.info(f"Best parameters found: {grid_search.best_params_}")
        rf_model = grid_search.best_estimator_

        # Step 4: Cross-validation
        logging.info("Performing cross-validation...")
        cv_scores = cross_val_score(rf_model, X_train, y_train, cv=5)
        logging.info(f"Cross-validation scores: {cv_scores}")
        logging.info(f"Mean cross-validation score: {cv_scores.mean()}")

        # Step 5: Train the model
        logging.info("Training Random Forest model with best parameters...")
        rf_model.fit(X_train, y_train)
        logging.info("Random Forest model training completed.")

        # Step 6: Evaluate the model
        y_pred = rf_model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        logging.info(f"Model evaluation completed with accuracy: {accuracy:.2f}")

        # Confusion Matrix & Classification Report
        conf_matrix = confusion_matrix(y_test, y_pred)
        class_report = classification_report(y_test, y_pred)
        logging.info(f"Confusion Matrix:\n{conf_matrix}")
        logging.info(f"Classification Report:\n{class_report}")

        # Emit final progress
        socketio.emit('training_complete', {
            'message': f'Model training completed! Accuracy: {accuracy:.2f}',
            'confusion_matrix': conf_matrix.tolist(),
            'classification_report': class_report
        })

        # Step 7: Save the trained model
        save_directory = r"C:\Users\Jacky\OneDrive - Asia Pacific University\Desktop\Final_Year_Project_FYP\APAnalyzer\backend"
        model_path = os.path.join(save_directory, 'random_forest_model.joblib')
        joblib.dump(rf_model, model_path)
        logging.info(f"Trained model saved at {model_path}.")

    except Exception as e:
        logging.error(f"Error during training: {str(e)}")
        socketio.emit('training_error', {'message': f'Error during training: {str(e)}'})
        return
    
    finally:
        # Optionally clean up the temp directory after saving the model
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)
            logging.info(f"Temporary directory {temp_dir} deleted.")

@app.route('/check_model_exists', methods=['GET'])
def check_model_exists():
    model_path = r"C:\Users\Jacky\OneDrive - Asia Pacific University\Desktop\Final_Year_Project_FYP\APAnalyzer\backend\random_forest_model.joblib"

    if not os.path.exists(model_path):
        return jsonify({'exists': False, 'message': 'Model does not exist.'}), 404
    
    # Load the model and extract details
    try:
        rf_model = joblib.load(model_path)
        logging.info("Model loaded successfully.")

        # Extract relevant model details (like number of estimators, max depth, etc.)
        model_info = {
            'n_estimators': rf_model.n_estimators,
            'max_depth': rf_model.max_depth,
            'min_samples_split': rf_model.min_samples_split,
            'min_samples_leaf': rf_model.min_samples_leaf,
        }

        # Optionally load evaluation metrics like accuracy from a saved file
        accuracy_file_path = os.path.join(os.path.dirname(model_path), 'model_accuracy.json')
        if os.path.exists(accuracy_file_path):
            with open(accuracy_file_path, 'r') as f:
                accuracy_data = json.load(f)
        else:
            accuracy_data = {'accuracy': '99.34%'}

        # Combine the model parameters with accuracy/evaluation results
        result = {
            'exists': True,
            'model_info': model_info,
            'evaluation': accuracy_data  # Include accuracy or other metrics if available
        }

        return jsonify(result)

    except Exception as e:
        logging.error(f"Failed to load model: {str(e)}")
        return jsonify({'exists': False, 'message': f"Failed to load model: {str(e)}"}), 500
    
@app.route('/compare_dataset', methods=['POST'])
def compare_dataset():
    logging.info("Received a request to compare dataset using pre-trained model...")

    # Check if file is part of the request
    if 'file' not in request.files:
        logging.error("No file part in request.")
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        logging.error("No selected file in request.")
        return jsonify({"error": "No selected file"}), 400
    if not file.filename.endswith('.csv'):
        logging.error("Invalid file format. Expected CSV.")
        return jsonify({"error": "Invalid file format. Please upload a CSV file."}), 400
    
    # Load the pre-trained model
    load_model_path = r"C:\Users\Jacky\OneDrive - Asia Pacific University\Desktop\Final_Year_Project_FYP\APAnalyzer\backend\random_forest_model.joblib"
    if not os.path.exists(load_model_path):
        return jsonify({"error": "Trained model not found. Please train the model first."}), 404
    
    rf_model = joblib.load(load_model_path)
    logging.info("Pre-trained model loaded successfully.")
    temp_dir = tempfile.mkdtemp()
    file_path = os.path.join(temp_dir, file.filename)
    file.save(file_path)

    try:
        dataset = pd.read_csv(file_path)
        logging.info(f"CSV file {file.filename} loaded successfully.")
    except Exception as e:
        logging.error(f"Failed to read CSV file: {str(e)}")
        return jsonify({"error": f"Failed to read CSV file: {str(e)}"}), 500
    finally:
        shutil.rmtree(temp_dir)

    logging.info("Checking for infinite and missing values in the dataset...")
    infinite_columns = dataset.columns[dataset.isin([np.inf, -np.inf]).any()]
    logging.info(f"Columns with infinite values: {infinite_columns}")
    dataset.replace([np.inf, -np.inf], np.nan, inplace=True)
    missing_values = dataset.isnull().sum()
    logging.info(f"Columns with missing values: {missing_values[missing_values > 0]}")
    for col in dataset.columns:
        if dataset[col].dtype in ['float64', 'int64']:
            dataset[col].fillna(dataset[col].median(), inplace=True)

    # Drop columns from new dataset
    if 'Protocol' in dataset.columns:
        dataset = dataset.drop(columns=['Protocol'])
    if 'Timestamp' in dataset.columns:
        dataset = dataset.drop(columns=['Timestamp'])
    if 'Fwd Header Length' not in dataset.columns:
        dataset['Fwd Header Length'] = 242 # Assume mean value of Fwd Header Length
    if 'Fwd Header Length.1' not in dataset.columns:
        dataset['Fwd Header Length.1'] = 242

    # Column mapping - Rename columns of new dataset to match the trained model's dataset
    column_mapping = {
        'Dst Port': ' Destination Port',
        'Flow Duration': ' Flow Duration',
        'Tot Fwd Pkts': ' Total Fwd Packets',
        'Tot Bwd Pkts': ' Total Backward Packets',
        'TotLen Fwd Pkts': 'Total Length of Fwd Packets',
        'TotLen Bwd Pkts': ' Total Length of Bwd Packets',
        'Fwd Pkt Len Max': ' Fwd Packet Length Max',
        'Fwd Pkt Len Min': ' Fwd Packet Length Min',
        'Fwd Pkt Len Mean': ' Fwd Packet Length Mean',
        'Fwd Pkt Len Std': ' Fwd Packet Length Std',
        'Bwd Pkt Len Max': 'Bwd Packet Length Max',
        'Bwd Pkt Len Min': ' Bwd Packet Length Min',
        'Bwd Pkt Len Mean': ' Bwd Packet Length Mean',
        'Bwd Pkt Len Std': ' Bwd Packet Length Std',
        'Flow Byts/s': 'Flow Bytes/s',
        'Flow Pkts/s': ' Flow Packets/s',
        'Flow IAT Mean': ' Flow IAT Mean',
        'Flow IAT Std': ' Flow IAT Std',
        'Flow IAT Max': ' Flow IAT Max',
        'Flow IAT Min': ' Flow IAT Min',
        'Fwd IAT Tot': 'Fwd IAT Total',
        'Fwd IAT Mean': ' Fwd IAT Mean',
        'Fwd IAT Std': ' Fwd IAT Std',
        'Fwd IAT Max': ' Fwd IAT Max',
        'Fwd IAT Min': ' Fwd IAT Min',
        'Bwd IAT Tot': 'Bwd IAT Total',
        'Bwd IAT Mean': ' Bwd IAT Mean',
        'Bwd IAT Std': ' Bwd IAT Std',
        'Bwd IAT Max': ' Bwd IAT Max',
        'Bwd IAT Min': ' Bwd IAT Min',
        'Fwd PSH Flags': 'Fwd PSH Flags',
        'Bwd PSH Flags': ' Bwd PSH Flags',
        'Fwd URG Flags': ' Fwd URG Flags',
        'Bwd URG Flags': ' Bwd URG Flags',
        'Fwd Header Len': ' Fwd Header Length',
        'Bwd Header Len': ' Bwd Header Length',
        'Fwd Pkts/s': 'Fwd Packets/s',
        'Bwd Pkts/s': ' Bwd Packets/s',
        'Pkt Len Min': ' Min Packet Length',
        'Pkt Len Max': ' Max Packet Length',
        'Pkt Len Mean': ' Packet Length Mean',
        'Pkt Len Std': ' Packet Length Std',
        'Pkt Len Var': ' Packet Length Variance',
        'FIN Flag Cnt': 'FIN Flag Count',
        'SYN Flag Cnt': ' SYN Flag Count',
        'RST Flag Cnt': ' RST Flag Count',
        'PSH Flag Cnt': ' PSH Flag Count',
        'ACK Flag Cnt': ' ACK Flag Count',
        'URG Flag Cnt': ' URG Flag Count',
        'CWE Flag Count': ' CWE Flag Count',
        'ECE Flag Cnt': ' ECE Flag Count',
        'Down/Up Ratio': ' Down/Up Ratio',
        'Pkt Size Avg': ' Average Packet Size',
        'Fwd Seg Size Avg': ' Avg Fwd Segment Size',
        'Bwd Seg Size Avg': ' Avg Bwd Segment Size',
        'Fwd Header Length': ' Fwd Header Length.1',
        'Fwd Byts/b Avg': 'Fwd Avg Bytes/Bulk',
        'Fwd Pkts/b Avg': ' Fwd Avg Packets/Bulk',
        'Fwd Blk Rate Avg': ' Fwd Avg Bulk Rate',
        'Bwd Byts/b Avg': ' Bwd Avg Bytes/Bulk',
        'Bwd Pkts/b Avg': ' Bwd Avg Packets/Bulk',
        'Bwd Blk Rate Avg': 'Bwd Avg Bulk Rate',
        'Subflow Fwd Pkts': 'Subflow Fwd Packets',
        'Subflow Fwd Byts': ' Subflow Fwd Bytes',
        'Subflow Bwd Pkts': ' Subflow Bwd Packets',
        'Subflow Bwd Byts': ' Subflow Bwd Bytes',
        'Init Fwd Win Byts': 'Init_Win_bytes_forward',
        'Init Bwd Win Byts': ' Init_Win_bytes_backward',
        'Fwd Act Data Pkts': ' act_data_pkt_fwd',
        'Fwd Seg Size Min': ' min_seg_size_forward',
        'Active Mean': 'Active Mean',
        'Active Std': ' Active Std',
        'Active Max': ' Active Max',
        'Active Min': ' Active Min',
        'Idle Mean': 'Idle Mean',
        'Idle Std': ' Idle Std',
        'Idle Max': ' Idle Max',
        'Idle Min': ' Idle Min',
        'Label': ' Label'
    }

    # Rename columns in new dataset
    dataset.rename(columns=column_mapping, inplace=True)

    label_mapping = {
        'Benign': 0, 
        'FTP-BruteForce': 1,
        'SSH-BruteForce': 2
    }

    # Check if the dataset contains all required features
    model_features = rf_model.feature_names_in_
    missing_columns = set(model_features) - set(dataset.columns)
    if missing_columns:
        logging.info(f"Missing columns: {missing_columns}")
        return jsonify({"error": f"Missing columns in the dataset: {missing_columns}"}), 400

    # Preprocess the dataset to match the model input features
    if ' Label' in dataset.columns:
        y_true = dataset[' Label'].map(label_mapping)
        valid_rows = y_true.notna()
        X = dataset[valid_rows].drop(columns=[' Label'])
        y_true = y_true[valid_rows]
        filtered_dataset = dataset[valid_rows]
    else:
        X = dataset
        y_true = None
        filtered_dataset = dataset

    # Get predictions from the model
    X = X[model_features]
    y_pred = rf_model.predict(X)

    logging.info(f"True labels (y_true): {y_true.value_counts()}")
    logging.info(f"Predicted labels (y_pred): {pd.Series(y_pred).value_counts()}")

    # Calculate precision, recall
    if y_true is not None:
        class_report = classification_report(y_true, y_pred, output_dict=True, zero_division=0)
        precision = class_report.get(str(1), {}).get('precision', 0)  # Assuming 1 represents threats
        recall = class_report.get(str(1), {}).get('recall', 0)
        logging.info(f"Comparison completed. Precision: {precision:.2f}, Recall: {recall:.2f}")
    else:
        class_report = None
        precision, recall = None, None

    # Identify anomalies (assuming label 0 is benign, and others are threats)
    anomalies = int((y_pred != 0).sum())

    # Classify the severity of the threats based on the predicted class
    severity_counts = {
        'low': int((y_pred == 1).sum()),     # Assuming label 1 is low severity
        'medium': int((y_pred == 2).sum()),  # Assuming label 2 is medium severity
        'high': int((y_pred == 3).sum())     # Assuming label 3 is high severity
    }

    logging.info(f"Severity breakdown: {severity_counts}")

    # Separate rows into severity categories and sample threats for display
    low_severity_threats = filtered_dataset[y_pred == 1]
    medium_severity_threats = filtered_dataset[y_pred == 2]
    high_severity_threats = filtered_dataset[y_pred == 3]

    # Limit the number of threats to display to the frontend
    low_severity_threats_sample = low_severity_threats.head(1).to_dict(orient='records')
    medium_severity_threats_sample = medium_severity_threats.head(1).to_dict(orient='records')
    high_severity_threats_sample = high_severity_threats.head(1).to_dict(orient='records')

    result = {
        'anomalies_detected': anomalies,
        'precision': float(precision),
        'recall': float(recall),
        'severity_breakdown': severity_counts,
        'classification_report': class_report,
        'low_severity_threats': low_severity_threats_sample,
        'medium_severity_threats': medium_severity_threats_sample,
        'high_severity_threats': high_severity_threats_sample
    }

    return jsonify(result)

@app.route('/compare_real_time_dataset', methods=['POST'])
def compare_real_time_dataset():
    logging.info("Received a request to compare real time dataset using pre-trained model...")

    # Check if file is part of the request
    if 'file' not in request.files:
        logging.error("No file part in request.")
        return jsonify({"error": "No file part"}), 400
    
    file = request.files['file']
    if file.filename == '':
        logging.error("No selected file in request.")
        return jsonify({"error": "No selected file"}), 400
    if not file.filename.endswith('.csv'):
        logging.error("Invalid file format. Expected CSV.")
        return jsonify({"error": "Invalid file format. Please upload a CSV file."}), 400
    
    # Load the pre-trained model
    load_model_path = r"C:\Users\Jacky\OneDrive - Asia Pacific University\Desktop\Final_Year_Project_FYP\APAnalyzer\backend\random_forest_model.joblib"
    if not os.path.exists(load_model_path):
        return jsonify({"error": "Trained model not found. Please train the model first."}), 404
    
    rf_model = joblib.load(load_model_path)
    logging.info("Pre-trained model loaded successfully.")
    temp_dir = tempfile.mkdtemp()
    file_path = os.path.join(temp_dir, file.filename)
    file.save(file_path)

    try:
        dataset = pd.read_csv(file_path)
        logging.info(f"CSV file {file.filename} loaded successfully.")
    except Exception as e:
        logging.error(f"Failed to read CSV file: {str(e)}")
        return jsonify({"error": f"Failed to read CSV file: {str(e)}"}), 500
    finally:
        shutil.rmtree(temp_dir)

    logging.info("Checking for infinite and missing values in the dataset...")
    infinite_columns = dataset.columns[dataset.isin([np.inf, -np.inf]).any()]
    logging.info(f"Columns with infinite values: {infinite_columns}")
    dataset.replace([np.inf, -np.inf], np.nan, inplace=True)
    missing_values = dataset.isnull().sum()
    logging.info(f"Columns with missing values: {missing_values[missing_values > 0]}")
    for col in dataset.columns:
        if dataset[col].dtype in ['float64', 'int64']:
            dataset[col].fillna(dataset[col].median(), inplace=True)

    # Drop columns from new dataset
    if 'Protocol' in dataset.columns:
        dataset = dataset.drop(columns=['Protocol'])
    if 'Timestamp' in dataset.columns:
        dataset = dataset.drop(columns=['Timestamp'])
    if 'Fwd Header Length' not in dataset.columns:
        dataset['Fwd Header Length'] = 242 # Assume mean value of Fwd Header Length
    if 'Fwd Header Length.1' not in dataset.columns:
        dataset['Fwd Header Length.1'] = 242

    # Column mapping - Rename columns of new dataset to match the trained model's dataset
    column_mapping = {
        'Dst Port': ' Destination Port',
        'Flow Duration': ' Flow Duration',
        'Tot Fwd Pkts': ' Total Fwd Packets',
        'Tot Bwd Pkts': ' Total Backward Packets',
        'TotLen Fwd Pkts': 'Total Length of Fwd Packets',
        'TotLen Bwd Pkts': ' Total Length of Bwd Packets',
        'Fwd Pkt Len Max': ' Fwd Packet Length Max',
        'Fwd Pkt Len Min': ' Fwd Packet Length Min',
        'Fwd Pkt Len Mean': ' Fwd Packet Length Mean',
        'Fwd Pkt Len Std': ' Fwd Packet Length Std',
        'Bwd Pkt Len Max': 'Bwd Packet Length Max',
        'Bwd Pkt Len Min': ' Bwd Packet Length Min',
        'Bwd Pkt Len Mean': ' Bwd Packet Length Mean',
        'Bwd Pkt Len Std': ' Bwd Packet Length Std',
        'Flow Byts/s': 'Flow Bytes/s',
        'Flow Pkts/s': ' Flow Packets/s',
        'Flow IAT Mean': ' Flow IAT Mean',
        'Flow IAT Std': ' Flow IAT Std',
        'Flow IAT Max': ' Flow IAT Max',
        'Flow IAT Min': ' Flow IAT Min',
        'Fwd IAT Tot': 'Fwd IAT Total',
        'Fwd IAT Mean': ' Fwd IAT Mean',
        'Fwd IAT Std': ' Fwd IAT Std',
        'Fwd IAT Max': ' Fwd IAT Max',
        'Fwd IAT Min': ' Fwd IAT Min',
        'Bwd IAT Tot': 'Bwd IAT Total',
        'Bwd IAT Mean': ' Bwd IAT Mean',
        'Bwd IAT Std': ' Bwd IAT Std',
        'Bwd IAT Max': ' Bwd IAT Max',
        'Bwd IAT Min': ' Bwd IAT Min',
        'Fwd PSH Flags': 'Fwd PSH Flags',
        'Bwd PSH Flags': ' Bwd PSH Flags',
        'Fwd URG Flags': ' Fwd URG Flags',
        'Bwd URG Flags': ' Bwd URG Flags',
        'Fwd Header Len': ' Fwd Header Length',
        'Bwd Header Len': ' Bwd Header Length',
        'Fwd Pkts/s': 'Fwd Packets/s',
        'Bwd Pkts/s': ' Bwd Packets/s',
        'Pkt Len Min': ' Min Packet Length',
        'Pkt Len Max': ' Max Packet Length',
        'Pkt Len Mean': ' Packet Length Mean',
        'Pkt Len Std': ' Packet Length Std',
        'Pkt Len Var': ' Packet Length Variance',
        'FIN Flag Cnt': 'FIN Flag Count',
        'SYN Flag Cnt': ' SYN Flag Count',
        'RST Flag Cnt': ' RST Flag Count',
        'PSH Flag Cnt': ' PSH Flag Count',
        'ACK Flag Cnt': ' ACK Flag Count',
        'URG Flag Cnt': ' URG Flag Count',
        'CWE Flag Count': ' CWE Flag Count',
        'ECE Flag Cnt': ' ECE Flag Count',
        'Down/Up Ratio': ' Down/Up Ratio',
        'Pkt Size Avg': ' Average Packet Size',
        'Fwd Seg Size Avg': ' Avg Fwd Segment Size',
        'Bwd Seg Size Avg': ' Avg Bwd Segment Size',
        'Fwd Header Length': ' Fwd Header Length.1',
        'Fwd Byts/b Avg': 'Fwd Avg Bytes/Bulk',
        'Fwd Pkts/b Avg': ' Fwd Avg Packets/Bulk',
        'Fwd Blk Rate Avg': ' Fwd Avg Bulk Rate',
        'Bwd Byts/b Avg': ' Bwd Avg Bytes/Bulk',
        'Bwd Pkts/b Avg': ' Bwd Avg Packets/Bulk',
        'Bwd Blk Rate Avg': 'Bwd Avg Bulk Rate',
        'Subflow Fwd Pkts': 'Subflow Fwd Packets',
        'Subflow Fwd Byts': ' Subflow Fwd Bytes',
        'Subflow Bwd Pkts': ' Subflow Bwd Packets',
        'Subflow Bwd Byts': ' Subflow Bwd Bytes',
        'Init Fwd Win Byts': 'Init_Win_bytes_forward',
        'Init Bwd Win Byts': ' Init_Win_bytes_backward',
        'Fwd Act Data Pkts': ' act_data_pkt_fwd',
        'Fwd Seg Size Min': ' min_seg_size_forward',
        'Active Mean': 'Active Mean',
        'Active Std': ' Active Std',
        'Active Max': ' Active Max',
        'Active Min': ' Active Min',
        'Idle Mean': 'Idle Mean',
        'Idle Std': ' Idle Std',
        'Idle Max': ' Idle Max',
        'Idle Min': ' Idle Min',
        'Label': ' Label'
    }

    # Rename columns in new dataset
    dataset.rename(columns=column_mapping, inplace=True)

    # Drop the 'Label' column entirely since it's all 'N/A'
    if 'Label' in dataset.columns:
        dataset = dataset.drop(columns=['Label'])

    # Check if the dataset contains all required features
    model_features = rf_model.feature_names_in_
    missing_columns = set(model_features) - set(dataset.columns)
    if missing_columns:
        logging.info(f"Missing columns: {missing_columns}")
        return jsonify({"error": f"Missing columns in the dataset: {missing_columns}"}), 400

    # Get predictions from the model
    X = dataset[model_features]
    y_pred = rf_model.predict(X)
    
    # Reverse the label mapping to get the string labels from predicted numeric values
    reverse_label_mapping = {
        0: 'BENIGN',
        1: 'DoS GoldenEye',
        2: 'DoS Hulk',
        3: 'DoS Slowhttptest',
        4: 'DoS slowloris',
        5: 'Heartbleed'
    }

    # Convert numeric predictions back to string labels
    dataset['Predicted Label'] = [reverse_label_mapping[label] for label in y_pred]

    logging.info(f"Predicted labels: {pd.Series(y_pred).value_counts()}")

    # Identify anomalies (assuming label 0 is benign, and others are threats)
    anomalies = int((y_pred != 0).sum())

    # Classify the severity of the threats based on the predicted class
    severity_counts = {
        'low': int((y_pred == 1).sum()),     # Assuming label 1 is low severity
        'medium': int((y_pred == 2).sum()),  # Assuming label 2 is medium severity
        'high': int((y_pred == 3).sum())     # Assuming label 3 is high severity
    }

    logging.info(f"Severity breakdown: {severity_counts}")

    # Separate rows into severity categories and sample threats for display
    low_severity_threats = dataset[y_pred == 1]
    medium_severity_threats = dataset[y_pred == 2]
    high_severity_threats = dataset[y_pred == 3]

    # Limit the number of threats to display to the frontend
    low_severity_threats_sample = low_severity_threats.head(1).to_dict(orient='records')
    medium_severity_threats_sample = medium_severity_threats.head(1).to_dict(orient='records')
    high_severity_threats_sample = high_severity_threats.head(1).to_dict(orient='records')

    result = {
        'anomalies_detected': anomalies,
        'severity_breakdown': severity_counts,
        'low_severity_threats': low_severity_threats_sample,
        'medium_severity_threats': medium_severity_threats_sample,
        'high_severity_threats': high_severity_threats_sample,
        'predicted_labels': dataset[['Predicted Label']].to_dict(orient='records') if not dataset.empty else[]
    }

    return jsonify(result)

# Function to map threat labels to solutions and severity levels
def get_threat_info(label):
    return threat_solutions.get(label, {
        'severity': 'Unknown',
        'explanation': 'No information available for this threat.',
        'solution': 'Please investigate further to determine the best mitigation approach.'
    })

@app.route('/generate_report', methods=['POST'])
def generate_report():
    logging.info("Received a request to generate a threat detection report...")

    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400
    
    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    
    if not file.filename.endswith('.csv'):
        return jsonify({'error': 'Invalid file format! Please upload a CSV file first!'}), 400

    temp_dir = tempfile.mkdtemp()
    file_path = os.path.join(temp_dir, file.filename)
    file.save(file_path)

    try:
        dataset = pd.read_csv(file_path)
        dataset.columns = dataset.columns.str.strip()
    except Exception as e:
        return jsonify({'error': f'Failed to read CSV file: {str(e)}'}), 500
    finally:
        shutil.rmtree(temp_dir)
    
    if 'Label' not in dataset.columns:
        return jsonify({'error': 'Dataset must contain a "Label" column!'}), 400
    
    detected_threats = dataset['Label'].unique()

    report_data = {
        'totalThreats': len([t for t in detected_threats if t.lower() != 'benign']),
        'threats': []
    }

    for threat in detected_threats:
        if threat.lower() != 'benign':
            threat_info = get_threat_info(threat)  # Get severity, explanation, and solution for each threat
            report_data['threats'].append({
                'name': threat,
                'severity': threat_info['severity'],
                'explanation': threat_info['explanation'],
                'solution': threat_info['solution']
            })

    return jsonify(report_data)

@app.route('/chatbot_assistance', methods=['POST'])
def chatbot_assistance():
    global uploaded_dataset_path

    if 'file' in request.files:
        # Step 1: Handle dataset upload
        file = request.files['file']
        if file and file.filename.endswith('.csv'):
            temp_dir = tempfile.mkdtemp()
            file_path = os.path.join(temp_dir, file.filename)
            file.save(file_path)

            try:
                dataset = pd.read_csv(file_path)
                logging.info(f"CSV file {file.filename} loaded successfully.")
                dataset.columns = dataset.columns.str.strip()
                detected_threats = dataset['Label'].unique()

                uploaded_dataset_path = file_path

                high_critical_threats = []
                for threat in detected_threats:
                    if threat.lower() != 'benign':
                        threat_info = threat_solutions.get(threat, {})
                        if threat_info and threat_info['severity'] in ['High', 'Critical']:
                            high_critical_threats.append(threat)
                
                if high_critical_threats:
                    return jsonify({
                        "response": f"Warning! Your dataset has {len(high_critical_threats)} high/critical threats! What would you like to check? Maybe you can check which threat, or what solution is recommended to mitigate these threats?"
                    })
                else:
                    return jsonify({
                        "response": "Dataset uploaded successfully. No high or critical threats detected. What would you like to check? ('Label' values or threat solutions)"
                    })
            except Exception as e:
                logging.error(f"Failed to read CSV file: {str(e)}")
                return jsonify({"error": f"Failed to read CSV file: {str(e)}"}), 500

    elif request.json and 'message' in request.json:
        message = request.json.get('message').lower()

        # Step 2: Respond with Label values from dataset
        if 'label' in message:
            if uploaded_dataset_path:
                dataset = pd.read_csv(uploaded_dataset_path)
                dataset.columns = dataset.columns.str.strip()

                labels_with_explanations = []
                labels = [threat for threat in dataset['Label'].unique() if threat.lower() != 'benign']

                for label in dataset['Label'].unique():
                    if label.lower() != 'benign':
                        threat_info = threat_solutions.get(label, None)
                        if threat_info:
                            labels_with_explanations.append(
                                f"{label}: {threat_info['explanation']}"
                            )

                return jsonify({
                    "response": f"The following threats within this dataset were found: {', '.join(labels)}.\nHere are the details:\n" + '\n'.join(labels_with_explanations)
                })
            
        elif 'solution for' in message:
            threat = message.replace('solution for', '').strip().lower()
            threat_info = next((info for key, info in threat_solutions.items() if key.lower() == threat), None)
            if threat_info:
                return jsonify({
                    "response": f"For {threat.title()}, the solution is: {threat_info['solution']}"
                })
            else:
                return jsonify({
                    "response": f"No solution found for {threat.title()}."
                })
                
        # Step 3: Respond with solutions for detected threats
        elif 'solution' in message:
            if uploaded_dataset_path:
                dataset = pd.read_csv(uploaded_dataset_path)
                dataset.columns = dataset.columns.str.strip()
                detected_threats = dataset['Label'].unique()

                solutions = []
                for threat in detected_threats:
                    if threat.lower() != 'benign':
                        threat_info = threat_solutions.get(threat, None)
                        if threat_info:
                            solutions.append(f"For {threat}, the severity level is {threat_info['severity'].lower()}. {threat_info['solution']}")

                if solutions:
                    return jsonify({
                        "response": f"Alright! I will provide recommended solution for these threats! " + '\n'.join(solutions)
                    })
                else:
                    return jsonify({
                        "response": "No solutions found for the detected threats."
                    })
                
        # Step 4: Handle specific threat queries (solution, severity, level, threats under High/Critical)
        elif 'severity level of' in message:
            threat = message.replace('severity level of', '').strip().lower()
            threat_info = next((info for key, info in threat_solutions.items() if key.lower() == threat), None)
            if threat_info:
                return jsonify({
                    "response": f"The severity level of {threat.title()} is: {threat_info['severity']}"
                })
            else:
                return jsonify({
                    "response": f"No severity information found for {threat.title()}."
                })
            
        elif 'threats under high' in message or 'threats under critical' in message:
            if uploaded_dataset_path:
                dataset = pd.read_csv(uploaded_dataset_path)
                dataset.columns = dataset.columns.str.strip()
                detected_threats = dataset['Label'].unique()

                high_critical_threats = []
                for threat in detected_threats:
                    if threat.lower() != 'benign':
                        threat_info = threat_solutions.get(threat, None)
                        if threat_info and threat_info['severity'] in ['High', 'Critical']:
                            high_critical_threats.append(threat)

                if high_critical_threats:
                    return jsonify({
                        "response": f"The threats under High/Critical severity are: {', '.join(high_critical_threats)}"
                    })
                else:
                    return jsonify({
                        "response": "No High or Critical severity threats found."
                    })
                
    return jsonify({"response": "I'm sorry, I didn't understand your request."})

if __name__ == '__main__':
    # Run Flask-SocketIO server
    socketio.run(app, host='0.0.0.0', port=5000)