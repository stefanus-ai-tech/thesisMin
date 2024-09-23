from flask import Flask, render_template, request, redirect, url_for, send_file, flash
import threading
import time
import os
import pyshark
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Use Agg backend which does not require a GUI
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
import psutil
import socket  # Added import for socket.AF_INET
import logging
from dotenv import load_dotenv
from telegram import Bot
from telegram.error import TelegramError
import asyncio


# Configure logging
logging.basicConfig(level=logging.INFO)

# Load environment variables from .env file
load_dotenv()

# Telegram bot configuration
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")  # Ensure this is set in your .env file
CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")      # Ensure this is set in your .env file

if not BOT_TOKEN or not CHAT_ID:
    raise ValueError("TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID must be set in the .env file.")

# Initialize the Telegram bot
bot = Bot(token=BOT_TOKEN)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)  # Needed for flashing messages

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

# Lock for thread-safe operations on settings
settings_lock = threading.Lock()
selected_interface = None
target_ip = None

def send_telegram(subject, body, attachment_paths=None):
    """
    Sends a message and optional attachments to a specified Telegram chat.
    
    :param subject: Subject of the message.
    :param body: Body text of the message.
    :param attachment_paths: List of file paths to send as attachments.
    """
    async def send():
        logging.info("Executing send coroutine...")
        try:
            full_message = f"📢 *{subject}*\n\n{body}"
            await bot.send_message(chat_id=CHAT_ID, text=full_message, parse_mode='Markdown')
            logging.info("Telegram message sent successfully!")

            if attachment_paths:
                for file_path in attachment_paths:
                    if os.path.exists(file_path):
                        with open(file_path, 'rb') as file:
                            await bot.send_document(chat_id=CHAT_ID, document=file)
                            logging.info(f"Sent attachment: {file_path}")
                    else:
                        logging.warning(f"Attachment file not found: {file_path}")
        except TelegramError as e:
            logging.error(f"Failed to send Telegram message: {e}")
    
    # Execute the asynchronous send function
    try:
        # Create a new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(send())
    except RuntimeError as e:
        # Handle the case where an event loop is already running
        logging.error(f"Asyncio run failed: {e}")
    finally:
        loop.close()

def classify_os(ttl, layer_type='ip'):
    """
    Classify the operating system based on TTL value ranges.
    
    :param ttl: TTL value.
    :param layer_type: Type of IP layer ('ip' or 'ipv6').
    :return: OS classification.
    """
    ttl_value = int(ttl)
    if layer_type == 'ip':
        if 0 <= ttl_value <= 64:
            return 'Linux'
        elif 65 <= ttl_value <= 128:
            return 'Windows'
        elif 129 <= ttl_value <= 254:
            return 'Solaris/AIX'
    elif layer_type == 'ipv6':
        # TTL equivalent in IPv6 is Hop Limit
        if 0 <= ttl_value <= 64:
            return 'Linux'
        elif 65 <= ttl_value <= 128:
            return 'Windows'
        elif 129 <= ttl_value <= 254:
            return 'Solaris/AIX'
    return 'Unknown'

def classify_protocol(packet):
    global last_udp_packet_time, udp_packet_count
    protocol_type = packet.transport_layer

    with settings_lock:
        current_target_ip = target_ip

    # Determine the destination IP based on available layer
    if 'IP' in packet:
        dest_ip = packet.ip.dst
        layer_type = 'ip'
    elif 'IPv6' in packet:
        dest_ip = packet.ipv6.dst
        layer_type = 'ipv6'
    else:
        dest_ip = None
        layer_type = None

    if protocol_type == 'UDP' and dest_ip == current_target_ip:
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
    """
    Extracts relevant details from a packet.
    
    Handles both IPv4 and IPv6 packets.
    
    :param packet: The captured packet.
    :return: A dictionary of packet details or None if required layers are missing.
    """
    try:
        protocol_type = packet.transport_layer

        # Determine if packet has IPv4 or IPv6
        if 'IP' in packet:
            source_address = packet.ip.src
            destination_address = packet.ip.dst
            ttl = packet.ip.ttl
            layer_type = 'ip'
        elif 'IPv6' in packet:
            source_address = packet.ipv6.src
            destination_address = packet.ipv6.dst
            ttl = packet.ipv6.hlim  # Hop Limit in IPv6 is equivalent to TTL
            layer_type = 'ipv6'
        else:
            logging.warning("Packet does not have IP or IPv6 layer. Skipping.")
            return None  # Skip packets without IP layers

        source_port = packet[packet.transport_layer].srcport
        destination_port = packet[packet.transport_layer].dstport
        packet_time = packet.sniff_time
        os_class = classify_os(ttl, layer_type=layer_type)
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
            'TTL/Hop Limit': ttl,
            'OS': os_class,
            'Packet Size': udp_packet_size,
            'Payload Size': udp_payload_size,
            'Detection': udpFlood
        }
    except AttributeError as e:
        logging.error(f"Attribute error while processing packet: {e}")
        return None
    except Exception as e:
        logging.error(f"Unexpected error while processing packet: {e}")
        return None

def filter_all_udp_traffic_file(packet):
    if hasattr(packet, 'udp'):
        return get_packet_details(packet)
    return None

def capture_bandwidth_history():
    global history
    history = []
    logging.info('Capturing Bandwidth History...')
    while not stop_event.is_set():
        net_io = psutil.net_io_counters()
        net_usage = net_io.bytes_sent + net_io.bytes_recv
        history.append((datetime.now(), net_usage))
        time.sleep(5)  # Short sleep interval for responsive stopping
    logging.info('Bandwidth History Capture Stopped!')

def plot_bandwidth_history(history):
    if len(history) < 2:
        logging.warning('Not enough data to plot.')
        return
    timestamps, net_usage = zip(*history)
    
    # Convert to datetime if not already
    if isinstance(timestamps[0], str):
        timestamps = [datetime.strptime(t, '%Y-%m-%d %H:%M:%S') for t in timestamps]
    
    data_rate_kBps = [
        (net_usage[i] - net_usage[i - 1]) / 1024 / (timestamps[i] - timestamps[i - 1]).total_seconds()
        for i in range(1, len(timestamps))
    ]
    plot_timestamps = [t.strftime('%H:%M:%S') for t in timestamps[1:]]
    
    logging.info('Plotting Bandwidth History...')
    plt.figure(figsize=(10, 6))
    plt.plot(plot_timestamps, data_rate_kBps, marker='o', linestyle='-', color='#7a6f6f')  # Pastel color
    plt.title('Network Bandwidth Usage Over Time')
    plt.xlabel('Timestamp')
    plt.ylabel('Data Transfer Rate (kB/s)')
    plt.xticks(rotation=45)
    plt.tight_layout()
    plot_file_path = './static/bandwidth_chart.png'
    plt.savefig(plot_file_path)
    plt.close()
    logging.info('Bandwidth History Plotting Complete!')

def capture_live_packets(interface, target_ip_address):
    global packet_details_list
    logging.info(f"Starting packet capture on interface: {interface}, target IP: {target_ip_address}")
    # Add a BPF filter to capture only UDP over IPv4 and IPv6 targeting the specified IP
    bpf_filter = f"udp and (ip or ip6) and dst host {target_ip_address}"
    capture = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)
    total_captured_packets = 0
    udp_flood_count = 0

    logging.info('Processing packets...')
    try:
        for raw_packet in capture.sniff_continuously():
            if stop_event.is_set():
                logging.info("Stop event set, stopping capture.")
                break
            total_captured_packets += 1
            packet_details = filter_all_udp_traffic_file(raw_packet)
            if packet_details:
                logging.info(packet_details)
                packet_details_list.append(packet_details)
                if packet_details['Detection'] == 'UDP flood detected':
                    udp_flood_count += 1

        logging.info('Capture complete')
        logging.info(f'Total Captured Packets: {total_captured_packets}')
        logging.info(f'UDP Floods Detected: {udp_flood_count}')
        logging.info('Packets processed')

        # Save packet details to Excel
        df = pd.DataFrame(packet_details_list)
        excel_file_path = './udp_details_attack_telegram.xlsx'
        df.to_excel(excel_file_path, index=False)
        logging.info(f'Data saved to {excel_file_path}')

        # Plot bandwidth history
        plot_bandwidth_history(history)

        # Define attachment paths
        attachment_paths = [excel_file_path, './static/bandwidth_chart.png']

        # Send summary via Telegram
        if udp_flood_count > 0:
            subject = '🚨 UDP Flood Alert!'
            body = (f"**Total UDP Floods Detected:** {udp_flood_count}\n"
                    f"**Total Captured Packets:** {total_captured_packets}\n"
                    "Please find the attached details and bandwidth chart.\n"
                    "Take immediate action!")
            logging.info('Sending Telegram message...')
            send_telegram(subject, body, attachment_paths=attachment_paths)
        else:
            subject = '✅ Network Status: All Clear'
            body = (f"**Total UDP Floods Detected:** {udp_flood_count}\n"
                    f"**Total Captured Packets:** {total_captured_packets}\n"
                    "The system is safe!")
            logging.info('Sending Telegram message...')
            send_telegram(subject, body, attachment_paths=attachment_paths)
    except Exception as e:
        logging.error(f"Error during capture: {e}")
    finally:
        capture.close()  # Ensure the capture is properly closed
        logging.info('Capture complete')

def get_default_private_ip():
    """Retrieve the default private IP address of the machine."""
    addrs = psutil.net_if_addrs()
    for iface, addr_list in addrs.items():
        for addr in addr_list:
            if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                return addr.address
    return '127.0.0.1'

def get_network_interfaces():
    """
    Retrieves a list of available network interfaces on the machine.
    
    :return: A list of interface names.
    """
    return list(psutil.net_if_addrs().keys())

@app.route('/')
def index():
    available_interfaces = get_network_interfaces()
    
    with settings_lock:
        current_interface = selected_interface
        current_target_ip = target_ip or get_default_private_ip()

    return render_template('index.html',
                           capture_running=capture_running,
                           history=history,
                           packet_details_list=packet_details_list,
                           interfaces=available_interfaces,
                           current_interface=current_interface,
                           current_target_ip=current_target_ip)

@app.route('/configure', methods=['GET', 'POST'])
def configure():
    available_interfaces = get_network_interfaces()
    
    if request.method == 'POST':
        selected = request.form.get('interface')
        target = request.form.get('target_ip')
        
        if not selected:
            flash('Please select a network interface.', 'error')
            return redirect(url_for('configure'))
        
        if not target:
            flash('Please enter a target IP address.', 'error')
            return redirect(url_for('configure'))
        
        with settings_lock:
            global selected_interface, target_ip
            selected_interface = selected
            target_ip = target

        flash('Configuration updated successfully!', 'success')
        return redirect(url_for('index'))
    
    with settings_lock:
        current_interface = selected_interface
        current_target_ip = target_ip or get_default_private_ip()
    
    return render_template('configure.html',
                           interfaces=available_interfaces,
                           current_interface=current_interface,
                           current_target_ip=current_target_ip)

@app.route('/start_capture', methods=['POST'])
def start_capture():
    global capture_thread, bandwidth_thread, capture_running, history, packet_details_list
    with settings_lock:
        interface = selected_interface
        ip = target_ip

    if not interface or not ip:
        flash('Please configure the interface and target IP before starting capture.', 'error')
        return redirect(url_for('configure'))

    if not capture_running:
        stop_event.clear()  # Reset the stop event here
        capture_running = True
        history = []
        packet_details_list = []
        capture_thread = threading.Thread(target=capture_live_packets, args=(interface, ip))
        bandwidth_thread = threading.Thread(target=capture_bandwidth_history)
        capture_thread.start()
        bandwidth_thread.start()
        flash('Packet capture started.', 'success')
    else:
        flash('Capture is already running.', 'info')
    return redirect(url_for('index'))

@app.route('/stop_capture', methods=['POST'])
def stop_capture():
    global capture_running, capture_thread, bandwidth_thread
    if capture_running:
        stop_event.set()
        capture_running = False
        if capture_thread is not None:
            capture_thread.join(timeout=10)  # Wait at most 10 seconds
            if capture_thread.is_alive():
                logging.warning("Capture thread did not terminate timely.")
        if bandwidth_thread is not None:
            bandwidth_thread.join(timeout=10)  # Wait at most 10 seconds
            if bandwidth_thread.is_alive():
                logging.warning("Bandwidth thread did not terminate timely.")
        plot_bandwidth_history(history)
        flash('Packet capture stopped.', 'success')
    else:
        flash('Capture is not running.', 'info')
    return redirect(url_for('index'))

@app.route('/download_excel')
def download_excel():
    excel_file_path = './udp_details_attack_telegram.xlsx'
    if os.path.exists(excel_file_path):
        return send_file(excel_file_path, as_attachment=True)
    else:
        flash("No Excel file available.", 'error')
        return redirect(url_for('index'))

@app.route('/download_plot')
def download_plot():
    plot_file_path = './static/bandwidth_chart.png'
    if os.path.exists(plot_file_path):
        return send_file(plot_file_path, as_attachment=True)
    else:
        flash("No plot available.", 'error')
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
