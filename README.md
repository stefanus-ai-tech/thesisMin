## Overview
`DDoS-UPD-TCP-Detection-System` is a Python-based application designed to capture and analyze network traffic, specifically focusing on UDP packets. It provides functionalities to monitor network bandwidth, classify protocols, and detect potential UDP flood attacks. The application also integrates with Telegram to send alerts and reports.

## Features
- **Packet Capture**: Captures live network packets on a specified interface and target IP address.
- **Bandwidth Monitoring**: Tracks network bandwidth usage over time and generates a plot of the data transfer rate.
- **Protocol Classification**: Classifies network protocols and detects UDP flood attacks based on packet count and payload size.
- **Telegram Integration**: Sends alerts and reports to a specified Telegram chat, including message attachments like Excel files and plots.
- **Network Interface Management**: Retrieves and manages available network interfaces on the machine.
- **Configuration Management**: Allows users to configure the network interface and target IP address for packet capture.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/mins-y/DDoS-UPD-TCP-Detection-System
   ```
2. Navigate to the project directory:
   ```bash
   cd DDoS-UPD-TCP-Detection-System
   ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Set up your Telegram bot token and chat ID in a `.env` file:
   ```plaintext
   TELEGRAM_BOT_TOKEN=your_bot_token
   TELEGRAM_CHAT_ID=your_chat_id
   ```

## Usage
1. Start the Flask application:
   ```bash
   python app.py
   ```
2. Access the web interface at `http://localhost:5000`.
3. Configure the network interface and target IP address.
4. Start the packet capture and monitor the network traffic.
5. Use the Telegram integration to receive alerts and reports.

## Code Structure
- **`app.py`**: The main application file containing all the core functionalities.
  - **Packet Capture**: Functions like `capture_live_packets` and `get_packet_details` handle packet capture and analysis.
  - **Bandwidth Monitoring**: Functions like `capture_bandwidth_history` and `plot_bandwidth_history` track and visualize network bandwidth.
  - **Protocol Classification**: Functions like `classify_protocol` and `classify_os` classify network protocols and operating systems.
  - **Telegram Integration**: The `send_telegram` function sends messages and attachments to Telegram.
  - **Network Interface Management**: Functions like `get_network_interfaces` and `get_default_private_ip` manage network interfaces.
  - **Configuration Management**: Functions like `configure` and `index` handle user configuration and interface rendering.

## Dependencies
- **Flask**: Web framework for building the application interface.
- **pyshark**: Library for capturing and analyzing network packets.
- **pandas**: Data manipulation library for handling packet data.
- **matplotlib**: Plotting library for generating bandwidth usage plots.
- **psutil**: Library for retrieving system and network information.
- **python-dotenv**: Library for managing environment variables.
- **python-telegram-bot**: Library for interacting with the Telegram Bot API.

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request with your changes.

## License
This project is licensed under the MIT License.
