import re
import os
import glob
import subprocess
import threading
import pyshark
import psutil
import socket
import asyncio
import traceback
from collections import deque
from datetime import datetime
from pyshark.tshark.tshark import get_process_path
from traffic_analysis import analyse_pcap
from risk_analysis import analyse_risk

#tshark = r"C:\Program Files\Wireshark\tshark.exe"
try:
    TSHARK_PATH = get_process_path()
except Exception:
    print("TShark not found.")
    TSHARK_PATH = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TRACE_FOLDER = os.path.join(BASE_DIR, "pcapTrace")

TRACE_DURATION = 180          # seconds (3 min)
TRACE_TIMEOUT = TRACE_DURATION + 10
MAX_TRACE_FILES = 100
PACKET_BUFFER_SIZE = 2000
ANALYSIS_ENABLED = True
ENABLE_PACKET_CAPTURE = True
ENABLE_TRACE_RECORDING = True
TRACE_FILENAME_FORMAT = "%Y%m%d_%H%M%S"
TRACE_EXTENSION = "pcapng"
LOCAL_IP = None

# Global Variables
packet_lock = threading.Lock()
packet_buffer = deque(maxlen=PACKET_BUFFER_SIZE)
capture_start_time = datetime.now()
packet_counter = 0
capture_errors = 0
trace_cleanup_lock = threading.Lock()
traffic_analysis_lock = threading.Lock()
analysis_thread = None


if not os.path.exists(TRACE_FOLDER):
    os.makedirs(TRACE_FOLDER)

# Active Network Interfaces
INTERFACES = []
INTERFACE_TYPES = {}

EXCLUDED_INTERFACES = (
    "loopback",
    "vmware",
    "virtualbox",
    "bluetooth",
    "docker",
    "hyper-v",
    "npcap loopback"
)

interface_addresses = psutil.net_if_addrs()
interface_stats = psutil.net_if_stats()


for name in interface_addresses.keys():

    if any(keyword in name.lower() for keyword in EXCLUDED_INTERFACES):
        continue

    if (
        name in interface_stats
        and interface_stats[name].isup
    ):
        INTERFACES.append(name)
        lower = name.lower()

        if any(keyword in lower for keyword in (
            "wi-fi",
            "wifi",
            "wireless",
            "wlan"
        )):
            INTERFACE_TYPES[name] = "Wireless"

        elif any(keyword in lower for keyword in (
            "ethernet",
            "eth",
            "lan"
        )):
            INTERFACE_TYPES[name] = "Ethernet"

        else:
            INTERFACE_TYPES[name] = "Unknown"


for interface in INTERFACES:

    ip_address = "N/A"

    for addr in interface_addresses[interface]:

        if addr.family == socket.AF_INET:
            ip_address = addr.address
            break

    speed = interface_stats[interface].speed
    speed_text = f"{speed} Mbps" if speed > 0 else "Unknown"

    if INTERFACE_TYPES[interface] == "Wireless" and LOCAL_IP is None:
        LOCAL_IP = ip_address

    elif LOCAL_IP is None:
        LOCAL_IP = ip_address

    print(
        f"✓ {interface:<20}"
        f"IP: {ip_address:<16}"
        f"Speed: {speed_text}"
    )

print("=" * 60)

# Get Source & Destination Address
def get_addresses(packet):

    try:

        # IPv4
        if hasattr(packet, "ip"):

            return (
                getattr(packet.ip, "src", "Unknown"),
                getattr(packet.ip, "dst", "Unknown")
            )

        # IPv6
        elif hasattr(packet, "ipv6"):

            return (
                getattr(packet.ipv6, "src", "Unknown"),
                getattr(packet.ipv6, "dst", "Unknown")
            )

        # Ethernet (ARP)
        elif hasattr(packet, "eth"):

            return (
                getattr(packet.eth, "src", "Unknown"),
                getattr(packet.eth, "dst", "Unknown")
            )

    except Exception:
        pass

    return ("Unknown", "Unknown")

# Get Application Protocol
def get_protocol(packet):

    try:
        # Application Protocols (Highest Priority)
        if hasattr(packet, "http2"):
            return "HTTP2"
        if hasattr(packet, "http"):
            return "HTTP"
        if hasattr(packet, "tls"):
            return "TLS"
        if hasattr(packet, "quic"):
            return "QUIC"
        if hasattr(packet, "dns"):
            return "DNS"
        if hasattr(packet, "mdns"):
            return "mDNS"
        if hasattr(packet, "ssdp"):
            return "SSDP"
        if hasattr(packet, "nbns"):
            return "NBNS"
        if hasattr(packet, "arp"):
            return "ARP"
        if hasattr(packet, "icmp"):
            return "ICMP"
        # Transport Layer
        if hasattr(packet, "tcp"):
            return "TCP"
        if hasattr(packet, "udp"):
            return "UDP"
        return packet.highest_layer.upper()

    except Exception:

        return "Unknown"

def get_packet_length(packet):

    try:
        return int(packet.length)
    except Exception:
        return 0

# Get Packet Information
def get_packet_info(packet):

    try:
        if hasattr(packet, "tcp"):
            return (
                f"{packet.tcp.srcport}"
                f" → "
                f"{packet.tcp.dstport}"
            )

        if hasattr(packet, "udp"):
            return (
                f"{packet.udp.srcport}"
                f" → "
                f"{packet.udp.dstport}"
            )
        
        if hasattr(packet, "arp"):
            opcode = getattr(packet.arp, "opcode", "")
            src_ip = getattr(packet.arp, "src_proto_ipv4", "")
            dst_ip = getattr(packet.arp, "dst_proto_ipv4", "")
            src_mac = getattr(packet.arp, "src_hw_mac", "")
            if opcode == "1":
                return f"Who has {dst_ip}?"
            elif opcode == "2":
                return f"{src_ip} is at {src_mac}"
            return "ARP"

        return packet.highest_layer

    except Exception:

        return "Unknown"

# Capture Packets
def capture_packets(interface):

    global packet_counter
    global capture_errors
    capture = None

    if not TSHARK_PATH:
        print("Packet Capture Disabled : TShark not found.")
        return

    try:

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        capture = pyshark.LiveCapture(
            interface=interface,
            tshark_path=TSHARK_PATH
        )


        for packet in capture.sniff_continuously():
            #print(packet.highest_layer)
            try:

                source, destination = get_addresses(packet)
                protocol = get_protocol(packet)
                transport = "Unknown"

                
                if hasattr(packet, "tcp"):
                    transport = "TCP"

                elif hasattr(packet, "udp"):
                    transport = "UDP"

                length = get_packet_length(packet)

                src_port = "N/A"
                dst_port = "N/A"

                # Packet Direction
                direction = "Internal"

                try:
                    if LOCAL_IP:
                        if source == LOCAL_IP:
                            direction = "Outgoing"

                        elif destination == LOCAL_IP:
                            direction = "Incoming"

                except Exception:
                    direction = "Unknown"


                if hasattr(packet, "tcp"):
                    src_port = getattr(packet.tcp, "srcport", "")
                    dst_port = getattr(packet.tcp, "dstport", "")

                elif hasattr(packet, "udp"):
                    src_port = getattr(packet.udp, "srcport", "")
                    dst_port = getattr(packet.udp, "dstport", "")

                with packet_lock:
                    packet_counter += 1
                    current_packet_id = packet_counter


                packet_timestamp = (
                    packet.sniff_time.timestamp()
                    if hasattr(packet, "sniff_time")
                    else datetime.now().timestamp()
                )


                packet_info = {
                    "id": current_packet_id,

                    "time": (
                        packet.sniff_time.strftime("%H:%M:%S")
                        if hasattr(packet, "sniff_time")
                        else datetime.now().strftime("%H:%M:%S")
                    ),

                    "timestamp": packet_timestamp,

                    "interface": interface,

                    "source": source,
                    "sourcePort": src_port,

                    "destination": destination,
                    "destinationPort": dst_port,

                    "direction": direction,

                    "protocol": protocol,
                    "transport": transport,

                    "length": length,

                    "info": get_packet_info(packet)
                }

                with packet_lock:
                    packet_buffer.append(packet_info)

            except Exception as e:

                capture_errors += 1
                print("=" * 60)
                print(f"Reason : {e}")
                traceback.print_exc()
                print("=" * 60)

    except Exception as e:
        capture_errors += 1
        print(f"Capture initialization failed for {interface}: {e}")
        traceback.print_exc()

    finally:
        if capture:
            capture.close()

# Start Capture
def start_capture():
    if not INTERFACES:
        print("No active interfaces found.")

        return

    for interface in INTERFACES:

        if ENABLE_PACKET_CAPTURE:
            threading.Thread(
                target=capture_packets,
                args=(interface,),
                daemon=True
            ).start()

            #print(f"Packet Capture Started : {interface}")

        if ENABLE_TRACE_RECORDING:
            threading.Thread(
                target=start_trace_recording,
                args=(interface,),
                daemon=True
            ).start()

            #print(f"Trace Recording Started : {interface}")

# Return Packets
def get_packets():
    with packet_lock:

        #print("=" * 60)
        #print("Packet Counter :", packet_counter)
        #print("Buffer Length  :", len(packet_buffer))
        #print("Buffer Max     :", packet_buffer.maxlen)
        #print("=" * 60)

        return list(packet_buffer)

# Capture Statistics
def get_capture_statistics():
    uptime = datetime.now() - capture_start_time

    with packet_lock:

        return {
            "interfaces": INTERFACES,
            "capturedPackets": packet_counter,
            "bufferSize": len(packet_buffer),
            "maxBuffer": packet_buffer.maxlen,
            "captureErrors": capture_errors,
            "uptime": str(uptime).split(".")[0]
        }

def cleanup_trace_files():
    with trace_cleanup_lock:
        files = sorted(
            glob.glob(os.path.join(TRACE_FOLDER, "*.pcapng")),
            key=os.path.getmtime
        )

        while len(files) > MAX_TRACE_FILES:
            try:
                os.remove(files[0])
                #print(f"Deleted old trace : {os.path.basename(files[0])}")
                files.pop(0)

            except Exception:
                traceback.print_exc()
                break

def start_analysis_thread(new_pcap):

    global analysis_thread

    if analysis_thread and analysis_thread.is_alive():
        #print("Background analysis already running.")
        return

    analysis_thread = threading.Thread(
        target=run_background_analysis,
        args=(new_pcap,),
        daemon=True
    )

    analysis_thread.start()

def run_background_analysis(new_pcap):

    with traffic_analysis_lock:

        try:

            analyse_pcap(new_pcap)
            analyse_risk()

        except Exception:

            traceback.print_exc()

def execute_analysis_pipeline(filepath):

    risk_result = {
        "status": "NOT EXECUTED"
    }

    result = analyse_pcap(filepath)

    if result.get("status") == "ERROR":

        print("=" * 60)
        print("Traffic Analysis Failed")
        print(result.get("message"))
        print("=" * 60)

        return result, risk_result
    """
    print("=" * 60)
    print("Traffic Analysis Updated Successfully")
    print(f"PCAP : {os.path.basename(filepath)}")
    print("=" * 60)

    print("=" * 60)
    print("Starting Risk Analysis")
    print("=" * 60)
    """
    try:

        risk_result = analyse_risk()

    except Exception as e:

        print("=" * 60)
        print(f"Risk Analysis Exception")
        print(f"PCAP : {os.path.basename(filepath)}")
        traceback.print_exc()

        risk_result = {
            "status": "ERROR",
            "message": str(e)
        }

    if risk_result.get("status") == "SUCCESS":
        """
        print("=" * 60)
        print("Risk Analysis Updated Successfully")
        print("=" * 60)
        """

    else:

        print("=" * 60)
        print("Risk Analysis Failed")
        print(risk_result.get("message"))
        print("=" * 60)

    return result, risk_result

def run_analysis_pipeline(filename):

    if not ANALYSIS_ENABLED:
        return

    try:

        #print("=" * 60)
        #print(f"Updating Traffic Analysis for : {filename}")
        #print("=" * 60)

        if not traffic_analysis_lock.acquire(False):
            print("Traffic Analysis already running.")
            return

        try:
            filepath = os.path.join(
                TRACE_FOLDER,
                filename
            )
            #print(f"PCAP File : {filepath}")
            
            if not os.path.isfile(filepath):
                print(f"PCAP not found : {filepath}")
                return
            
            result, risk_result = execute_analysis_pipeline(filepath)

        finally:
            traffic_analysis_lock.release()
        """
        print(f"Analysis completed for : {filename}")

        print("=" * 70)
        print("Analysis Pipeline Completed")
        print(f"Generated        : {datetime.now().strftime('%d-%b-%Y %H:%M:%S')}")
        print(f"Traffic Analysis : {result.get('status')}")
        print(f"Risk Analysis    : {risk_result.get('status')}")
        print("=" * 70)
        """
    except Exception as e:

        print("=" * 60)
        print(f"Traffic Analysis Failed : {e}")
        traceback.print_exc()
        print("=" * 60)

def start_trace_recording(interface):
    if not TSHARK_PATH:
        return

    tshark = TSHARK_PATH

    while True:
        analysis_required = False

        safe_interface = re.sub(
            r'[^A-Za-z0-9_-]',
            "_",
            interface
        )

        filename = (
            f"{safe_interface}_"
            f"{datetime.now().strftime(TRACE_FILENAME_FORMAT)}."
            f"{TRACE_EXTENSION}"
        )
        
        filepath = os.path.join(
            TRACE_FOLDER,
            filename
        )
        #print(f"Starting Recording : {filename}")

        try:
            result = subprocess.run(
                [
                    tshark,
                    "-i",
                    interface,
                    "-a",
                    f"duration:{TRACE_DURATION}",
                    "-F",
                    "pcapng",
                    "-w",
                    filepath
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=TRACE_TIMEOUT,
                check=False
            )

            if result.returncode != 0:
                print("=" * 60)
                print(f"TShark exited with code {result.returncode}")
                print("=" * 60)

                continue

            if (
                os.path.exists(filepath)
                and os.path.getsize(filepath) > 0
            ):
                analysis_required = True
                #print(f"Recording Completed : {filename}")
                    
            try:

                if os.path.exists(filepath):

                    if os.path.getsize(filepath) == 0:

                        os.remove(filepath)
                        print(f"Removed empty trace : {filename}")

            except Exception as e:
                print("=" * 60)
                print(f"Trace Recording Failed : {filename}")
                print(f"Reason : {e}")
                traceback.print_exc()
                print("=" * 60)

        except Exception as e:
            print(f"Trace recording failed on {interface}: {e}")
            traceback.print_exc()
            
        #print("Checking Trace Folder Cleanup...")
        cleanup_trace_files()

        if analysis_required and ANALYSIS_ENABLED:
            start_analysis_thread(filepath)

        """
        if analysis_required and ANALYSIS_ENABLED:

            global analysis_thread
            if (
                analysis_thread is None
                or
                not analysis_thread.is_alive()
            ):
                analysis_thread = threading.Thread(
                    name="TrafficRiskAnalysis",
                    target=run_analysis_pipeline,
                    args=(filename,),
                    daemon=True
                )
                analysis_thread.start()
        """

def get_connection_type():

    if not INTERFACES:
        return "Unknown"

    return INTERFACE_TYPES.get(
        INTERFACES[0],
        "Unknown"
    )


"""
def get_packet_context(
        packets,
        packet_number,
        window_size=5
):

    if not packets:
        return []

    selected_index = None

    for index, packet in enumerate(packets):

        if packet.get("id") == packet_number:
            selected_index = index
            break

    if selected_index is None:
        return []

    start = max(0, selected_index - window_size)

    end = min(
        len(packets),
        selected_index + window_size + 1
    )

    return packets[start:end]
"""

def get_packet_context(
        packets,
        packet_number,
        window_size=5
):
    """
    Always tries to return
    (2 * window_size + 1) packets.

    Middle:
        5 before + current + 5 after

    Beginning:
        shift window forward

    End:
        shift window backward

    If total packets < required,
    return all packets.
    """

    if not packets:
        return []

    selected_index = None

    for index, packet in enumerate(packets):

        if packet.get("id") == packet_number:
            selected_index = index
            break

    if selected_index is None:
        return []

    total_packets = len(packets)
    required_packets = (window_size * 2) + 1

    # Entire capture smaller than window
    if total_packets <= required_packets:
        return packets

    # Initial window
    start = selected_index - window_size
    end = selected_index + window_size + 1

    # Beginning of buffer
    if start < 0:
        end += abs(start)
        start = 0

    # End of buffer
    if end > total_packets:
        shift = end - total_packets
        start -= shift
        end = total_packets

        if start < 0:
            start = 0

    return packets[start:end]
"""
if packet.highest_layer == "DHCP":

    options = []

    packet.bootp.option_type
    packet.bootp.option_value
    packet.bootp.option_length

    # Extract DHCP Parameter Request List (Option 55)
    # Build:
    # [1,3,6,15,119,252]

    if hasattr(packet, "bootp"):

        print("=" * 80)
        print(packet.bootp)
        print("=" * 80)

    dhcp_info = fingerprint(options)
    device_cache[mac]["dhcpFingerprint"] = dhcp_info
"""