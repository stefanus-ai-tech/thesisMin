from flask import Flask, render_template, request, redirect, url_for, send_file
import threading
import time
import os
import pyshark
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Use Agg backend which does not require a GUI
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
import psutil
import logging
logging.basicConfig(level=logging.INFO)

app = Flask(__name__)

# Use an Event for better thread management
stop_event = threading.Event()

# Global variables to control the capture
capture_thread = None
bandwidth_thread = None

capture_running = False
history = []
packet_details_list = []

# Global variables for classify protocol function
last_udp_packet_time = datetime.now()
udp_packet_count = 0
udp_flood_threshold = 5  # First 5 potential UDP floods will not be detected for accuracy
time_window = timedelta(seconds=10)
payload_size_threshold = 1300  # Threshold for UDP flood detection

# List of port numbers and their corresponding names
port_number_mapping = {
    53: 'DNS',
    54: 'IANA',
    67: 'DHCP Server',
    68: 'DHCP Client',
    69: 'TFTP',
    161: 'SNMP',
    162: 'SNMP Trap',
    514: 'Syslog',
    123: 'NTP',
    1812: 'RADIUS Authentication',
    1813: 'RADIUS Accounting',
}

sender_email = 'stefanusaitech@gmail.com'
receiver_email = 'stefanusadriirawan@gmail.com'
app_password = 'your_app_password'

def send_email(subject, body, attachment_path=None):
    message = MIMEText(body)
    message['From'] = sender_email
    message['To'] = receiver_email
    message['Subject'] = subject

    try:
        with smtplib.SMTP('internal.smtp.server.com', 25) as server:  # Use the internal SMTP server that doesn't require authentication
            server.sendmail(sender_email, receiver_email, message.as_string())
            print("Email sent successfully without authentication!")
    except Exception as e:
        print(f"Failed to send email: {e}")

def classify_os(ttl):
    # Classify the operating system based on TTL value ranges
    ttl_value = int(ttl)
    if 0 <= ttl_value <= 64:
        return 'Linux'
    elif 65 <= ttl_value <= 128:
        return 'Windows'
    elif 129 <= ttl_value <= 254:
        return 'Solaris/AIX'
    else:
        return 'Unknown'

def classify_protocol(packet):
    global last_udp_packet_time, udp_packet_count
    protocol_type = packet.transport_layer
    dest_ip = packet.ip.dst if hasattr(packet, 'ip') and hasattr(packet.ip, 'dst') else None

    if protocol_type == 'UDP' and dest_ip == '192.168.43.135':
        current_time = datetime.now()
        time_difference = current_time - last_udp_packet_time

        if time_difference > time_window:
            udp_packet_count = 0

        udp_packet_count += 1
        last_udp_packet_time = current_time

        udp_payload_size = int(packet.length) - 8  # Subtracting UDP header size

        if udp_payload_size > payload_size_threshold and udp_packet_count > udp_flood_threshold:
            return 'UDP flood'

    return 'Unknown'

def classify_port(port):
    return port_number_mapping.get(int(port), 'Unknown')

def get_packet_details(packet):
    protocol_type = packet.transport_layer
    source_address = packet.ip.src
    source_port = packet[packet.transport_layer].srcport
    destination_address = packet.ip.dst
    destination_port = packet[packet.transport_layer].dstport
    packet_time = packet.sniff_time
    ttl = packet.ip.ttl
    os = classify_os(ttl)
    protocol = classify_protocol(packet)

    udpFlood = 'Not UDP flood'
    if protocol == 'UDP flood':
        udpFlood = 'UDP flood detected'

    source_port_name = classify_port(source_port)
    destination_port_name = classify_port(destination_port)
    udp_packet_size = len(packet)
    udp_payload_size = int(packet.length) - 8 if hasattr(packet, 'length') else 0

    return {
        'Packet Timestamp': packet_time,
        'Protocol type': protocol_type,
        'Source address': source_address,
        'Source port': source_port,
        'Source port name': source_port_name,
        'Destination address': destination_address,
        'Destination port': destination_port,
        'Destination port name': destination_port_name,
        'TTL': ttl,
        'OS': os,
        'Packet Size': udp_packet_size,
        'Payload Size': udp_payload_size,
        'Detection': udpFlood
    }

def filter_all_udp_traffic_file(packet):
    if hasattr(packet, 'udp'):
        return get_packet_details(packet)

def capture_bandwidth_history():
    global history
    history = []
    print('Capturing Bandwidth History...')
    while not stop_event.is_set():
        net_usage = psutil.net_io_counters().bytes_sent + psutil.net_io_counters().bytes_recv
        history.append((datetime.now(), net_usage))
        time.sleep(5)  # Short sleep interval for responsive stopping
    print('Bandwidth History Capture Stopped!')

def plot_bandwidth_history(history):
    if len(history) < 2:
        print('Not enough data to plot.')
        return
    timestamps, net_usage = zip(*history)
    data_rate_kBps = [(net_usage[i] - net_usage[i - 1]) / 1024 / (timestamps[i] - timestamps[i - 1]).total_seconds()
                      for i in range(1, len(timestamps))]
    plot_timestamps = [t.strftime('%H:%M:%S') for t in timestamps[1:]]

    print('Plotting Bandwidth History...')
    plt.figure(figsize=(10, 6))
    plt.plot(plot_timestamps, data_rate_kBps, marker='o', linestyle='-', color='#7a6f6f')  # Pastel color
    plt.title('Network Bandwidth Usage Over Time')
    plt.xlabel('Timestamp')
    plt.ylabel('Data Transfer Rate (kB/s)')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig('./static/bandwidth_chart.png')
    plt.close()
    print('Bandwidth History Plotting Complete!')

def capture_live_packets():
    global packet_details_list
    logging.info("Starting packet capture...")
    capture = pyshark.LiveCapture(interface='wlan0')  # Adjust the interface as needed
    total_captured_packets = 0
    udp_flood_count = 0

    print('\nProcessing packets...')
    try:
        for raw_packet in capture.sniff_continuously():
            if stop_event.is_set():
                logging.info("Stop event set, stopping capture.")
                break
            total_captured_packets += 1
            packet_details = filter_all_udp_traffic_file(raw_packet)
            if packet_details:
                print(packet_details)
                print("")
                packet_details_list.append(packet_details)
                if packet_details['Detection'] == 'UDP flood detected':
                    udp_flood_count += 1

        print('Capture complete')
        print(f'Total Captured Packets: {total_captured_packets}')
        print(f'UDP Floods Detected: {udp_flood_count}')
        print('Packets processed')

        # Save packet details to Excel
        df = pd.DataFrame(packet_details_list)
        excel_file_path = './udp_details_attack_email.xlsx'
        df.to_excel(excel_file_path, index=False)
        print(f'Data saved to {excel_file_path}')

        # Send summary email
        if udp_flood_count > 0:
            subject = 'UDP Flood Summaries'
            body = (f'Total UDP Floods Detected: {udp_flood_count} from total captured packets: {total_captured_packets}.'
                    '\nWe attach the detail in Excel format.\nTake action immediately!')
            send_email(subject, body, attachment_path=[excel_file_path, './static/bandwidth_chart.png'])
        else:
            print(f'Total UDP Floods Detected: {udp_flood_count} from total captured packets: {total_captured_packets}.\nThe system is safe!')
    except Exception as e:
        print(f"Error during capture: {e}")
    finally:
        capture.close()  # Ensure the capture is properly closed
        print('Capture complete')   
        
        
@app.route('/')
def index():
    return render_template('index.html', capture_running=capture_running, history=history, packet_details_list=packet_details_list)

@app.route('/start_capture', methods=['POST'])
def start_capture():
    global capture_thread, bandwidth_thread, capture_running, history, packet_details_list
    if not capture_running:
        stop_event.clear()  # Reset the stop event here
        capture_running = True
        history = []
        packet_details_list = []
        capture_thread = threading.Thread(target=capture_live_packets)
        bandwidth_thread = threading.Thread(target=capture_bandwidth_history)
        capture_thread.start()
        bandwidth_thread.start()
    return redirect(url_for('index'))

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    global capture_running, capture_thread, bandwidth_thread
    stop_event.set()
    capture_running = False
    if capture_thread is not None:
        capture_thread.join(timeout=10)  # Wait at most 10 seconds
        if capture_thread.is_alive():
            print("Capture thread did not terminate timely.")
    if bandwidth_thread is not None:
        bandwidth_thread.join(timeout=10)  # Wait at most 10 seconds
        if bandwidth_thread.is_alive():
            print("Bandwidth thread did not terminate timely.")
    plot_bandwidth_history(history)
    return redirect(url_for('index'))

@app.route('/download_excel')
def download_excel():
    excel_file_path = './udp_details_attack_email.xlsx'
    if os.path.exists(excel_file_path):
        return send_file(excel_file_path, as_attachment=True)
    else:
        return "No Excel file available."

@app.route('/download_plot')
def download_plot():
    plot_file_path = './static/bandwidth_chart.png'
    if os.path.exists(plot_file_path):
        return send_file(plot_file_path, as_attachment=True)
    else:
        return "No plot available."

if __name__ == '__main__':
    app.run(debug=True)
