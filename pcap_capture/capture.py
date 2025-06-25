# pcap_capture/capture.py

import pyshark
import os
import datetime
from config import Config

def capture_traffic(ip, duration=30):
    """
    Captures packets related to the specified IP for forensic analysis.
    Stores output PCAP in logs/pcaps/ directory.
    """
    try:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{ip.replace('.', '_')}_{timestamp}.pcap"
        filepath = os.path.join(Config.PCAP_FOLDER, filename)

        os.makedirs(Config.PCAP_FOLDER, exist_ok=True)

        print(f"📦 Capturing packets for {ip} ...")
        capture = pyshark.LiveCapture(interface='Wi-Fi', output_file=filepath, display_filter=f"ip.addr == {ip}")
        capture.sniff(timeout=duration)
        print(f"✅ PCAP saved: {filepath}")

    except Exception as e:
        print(f"❌ PCAP capture failed for {ip}: {e}")
