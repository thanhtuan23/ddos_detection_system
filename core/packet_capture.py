# core/packet_capture.py
import time
import queue
import threading
import logging
import socket
import struct
from typing import Dict, Any, List, Optional, Tuple, Set
import ctypes
from scapy.all import sniff, get_if_list, conf
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
import numpy as np

class PacketCapture:
    """
    Captures network packets and extracts flow information for analysis.
    """
    
    def __init__(self, interface: str, packet_queue: queue.Queue,
                 capture_filter: Optional[str] = None, buffer_size: int = 1000,
                 max_packets_per_flow: int = 20):
        """
        Initialize the packet capture component.
        
        Args:
            interface: Network interface to capture from
            packet_queue: Queue to send flow data for analysis
            capture_filter: BPF filter for packet capture
            buffer_size: Maximum number of flows to keep in memory
            max_packets_per_flow: Maximum number of packets to analyze per flow
        """
        self.logger = logging.getLogger("ddos_detection_system.core.packet_capture")
        
        # Validate interface
        available_interfaces = get_if_list()
        if interface not in available_interfaces:
            self.logger.warning(f"Interface {interface} not found. Available interfaces: {available_interfaces}")
            interface = conf.iface
            self.logger.info(f"Using default interface: {interface}")
        
        self.interface = interface
        self.packet_queue = packet_queue
        self.capture_filter = capture_filter or "ip"
        self.buffer_size = buffer_size
        self.max_packets_per_flow = max_packets_per_flow
        
        # Flow table: key = flow_key, value = flow_data
        self.flow_table = {}
        
        # Flow expiry table: key = flow_key, value = last_seen_time
        self.flow_expiry = {}
        
        # Counters for statistics
        self.stats = {
            'total_packets': 0,
            'processed_packets': 0,
            'dropped_packets': 0,
            'total_flows': 0,
            'current_flows': 0,
            'expired_flows': 0,
            'start_time': 0
        }
        
        # Threading control
        self.running = False
        self.capture_thread = None
        self.cleanup_thread = None
        self.lock = threading.RLock()
        
        # Initialize wellknown ports set
        self._init_wellknown_ports()
        
        self.logger.info(f"Packet capture initialized on interface {interface} with filter: {capture_filter}")
    
    def _init_wellknown_ports(self):
        """Initialize the set of well-known ports."""
        self.wellknown_ports = set()
        
        # Common service ports
        for port in [20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 5432, 8080, 8443]:
            self.wellknown_ports.add(port)
        
        # Streaming service ports
        for port in [1935, 8080, 8443, 1935, 3478, 19302, 443, 80]:
            self.wellknown_ports.add(port)
    
    def start_capture(self):
        """Start packet capture in a separate thread."""
        with self.lock:
            if self.running:
                self.logger.warning("Packet capture already running")
                return
            
            self.running = True
            self.stats['start_time'] = time.time()
            
            # Start capture thread
            self.capture_thread = threading.Thread(target=self._capture_packets)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            
            # Start cleanup thread
            self.cleanup_thread = threading.Thread(target=self._cleanup_old_flows)
            self.cleanup_thread.daemon = True
            self.cleanup_thread.start()
            
            self.logger.info(f"Started packet capture on interface {self.interface}")
    
    def stop_capture(self):
        """Stop packet capture."""
        with self.lock:
            if not self.running:
                self.logger.warning("Packet capture not running")
                return
            
            self.running = False
            
            # Wait for threads to terminate
            if self.capture_thread:
                self.capture_thread.join(timeout=2.0)
            
            if self.cleanup_thread:
                self.cleanup_thread.join(timeout=2.0)
            
            self.logger.info("Stopped packet capture")
    
    def _capture_packets(self):
        """Thread function to capture packets."""
        try:
            self.logger.info(f"Starting packet capture on {self.interface} with filter: {self.capture_filter}")
            
            # Use scapy to sniff packets
            sniff(
                iface=self.interface,
                filter=self.capture_filter,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda p: not self.running
            )
        except Exception as e:
            self.logger.error(f"Error in packet capture: {e}", exc_info=True)
            self.running = False
    
    def _process_packet(self, packet):
        """
        Process a captured packet.
        
        Args:
            packet: Scapy packet object
        """
        try:
            with self.lock:
                self.stats['total_packets'] += 1
                
                # Check if packet has IP layer
                if IP in packet:
                    ip_layer = packet[IP]
                    protocol = ip_layer.proto
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    ip_version = 4
                elif IPv6 in packet:
                    ip_layer = packet[IPv6]
                    protocol = ip_layer.nh
                    src_ip = ip_layer.src
                    dst_ip = ip_layer.dst
                    ip_version = 6
                else:
                    self.stats['dropped_packets'] += 1
                    return
                
                # Process based on protocol
                if TCP in packet:
                    self._process_tcp_packet(packet, ip_layer, protocol, src_ip, dst_ip, ip_version)
                elif UDP in packet:
                    self._process_udp_packet(packet, ip_layer, protocol, src_ip, dst_ip, ip_version)
                elif ICMP in packet:
                    self._process_icmp_packet(packet, ip_layer, protocol, src_ip, dst_ip, ip_version)
                elif ICMPv6EchoRequest in packet:
                    self._process_icmp_packet(packet, ip_layer, protocol, src_ip, dst_ip, ip_version)
                else:
                    # Other protocol, create a basic flow
                    flow_key = f"{src_ip}-{dst_ip}-{protocol}"
                    self._update_flow(flow_key, packet, ip_layer, protocol, src_ip, dst_ip, None, None, ip_version)
                
                self.stats['processed_packets'] += 1
                
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}", exc_info=True)
            self.stats['dropped_packets'] += 1
    
    def _process_tcp_packet(self, packet, ip_layer, protocol, src_ip, dst_ip, ip_version):
        """Process a TCP packet."""
        tcp_layer = packet[TCP]
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        
        # Create bidirectional flow key (smaller IP/port first for consistency)
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-TCP"
            direction = "forward"
        else:
            flow_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-TCP"
            direction = "backward"
        
        # Update flow information
        self._update_flow(flow_key, packet, ip_layer, protocol, src_ip, dst_ip, src_port, dst_port, ip_version, direction)
    
    def _process_udp_packet(self, packet, ip_layer, protocol, src_ip, dst_ip, ip_version):
        """Process a UDP packet."""
        udp_layer = packet[UDP]
        src_port = udp_layer.sport
        dst_port = udp_layer.dport
        
        # Create bidirectional flow key
        if src_ip < dst_ip or (src_ip == dst_ip and src_port < dst_port):
            flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-UDP"
            direction = "forward"
        else:
            flow_key = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}-UDP"
            direction = "backward"
        
        # Update flow information
        self._update_flow(flow_key, packet, ip_layer, protocol, src_ip, dst_ip, src_port, dst_port, ip_version, direction)
    
    def _process_icmp_packet(self, packet, ip_layer, protocol, src_ip, dst_ip, ip_version):
        """Process an ICMP packet."""
        # ICMP has no ports, use type and code
        if ICMP in packet:
            icmp_type = packet[ICMP].type
            icmp_code = packet[ICMP].code
        elif ICMPv6EchoRequest in packet:
            icmp_type = packet[ICMPv6EchoRequest].type
            icmp_code = 0  # Simplified for IPv6
        else:
            icmp_type = 0
            icmp_code = 0
        
        # Create flow key
        proto_name = "ICMPv6" if ip_version == 6 else "ICMP"
        flow_key = f"{src_ip}-{dst_ip}-{proto_name}-{icmp_type}-{icmp_code}"
        
        # Update flow information
        self._update_flow(flow_key, packet, ip_layer, protocol, src_ip, dst_ip, None, None, ip_version)
    
    def _update_flow(self, flow_key, packet, ip_layer, protocol, src_ip, dst_ip, src_port, dst_port, ip_version, direction="forward"):
        """
        Update flow information with a new packet.
        
        Args:
            flow_key: Unique identifier for the flow
            packet: Original packet
            ip_layer: IP layer of the packet
            protocol: Protocol number
            src_ip: Source IP
            dst_ip: Destination IP
            src_port: Source port (if applicable)
            dst_port: Destination port (if applicable)
            ip_version: IP version (4 or 6)
            direction: Packet direction ("forward" or "backward")
        """
        # Get current time
        current_time = time.time()
        
        # Initialize flow if it doesn't exist
        if flow_key not in self.flow_table:
            self.flow_table[flow_key] = {
                'flow_key': flow_key,
                'protocol': protocol,
                'ip_version': ip_version,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'start_time': current_time,
                'last_time': current_time,
                'packets': 0,
                'bytes': 0,
                'packet_sizes': [],
                'packet_times': [],
                'inter_arrival_times': [],
                'tcp_flags': {'SYN': 0, 'ACK': 0, 'FIN': 0, 'RST': 0, 'PSH': 0, 'URG': 0},
                'packet_lengths': {'forward': [], 'backward': []},
                'fwd_packets': 0,
                'bwd_packets': 0,
                'fwd_bytes': 0,
                'bwd_bytes': 0,
                'init_win_bytes_forward': 0,
                'init_win_bytes_backward': 0,
                'analyzed': False
            }
            
            # Record window size for TCP
            if TCP in packet:
                tcp_layer = packet[TCP]
                if direction == "forward":
                    self.flow_table[flow_key]['init_win_bytes_forward'] = tcp_layer.window
                else:
                    self.flow_table[flow_key]['init_win_bytes_backward'] = tcp_layer.window
            
            # Update stats
            self.stats['total_flows'] += 1
            self.stats['current_flows'] += 1
        
        # Get flow data
        flow = self.flow_table[flow_key]
        
        # Update flow expiry time
        self.flow_expiry[flow_key] = current_time
        
        # Update basic stats
        flow['last_time'] = current_time
        flow['packets'] += 1
        
        # Get packet size
        packet_size = len(packet)
        flow['bytes'] += packet_size
        flow['packet_sizes'].append(packet_size)
        
        # Update directional stats
        if direction == "forward":
            flow['fwd_packets'] += 1
            flow['fwd_bytes'] += packet_size
            flow['packet_lengths']['forward'].append(packet_size)
        else:
            flow['bwd_packets'] += 1
            flow['bwd_bytes'] += packet_size
            flow['packet_lengths']['backward'].append(packet_size)
        
        # Update packet timing
        flow['packet_times'].append(current_time)
        
        # Calculate inter-arrival time if not first packet
        if len(flow['packet_times']) > 1:
            inter_arrival = current_time - flow['packet_times'][-2]
            flow['inter_arrival_times'].append(inter_arrival)
        
        # Update TCP flags if applicable
        if TCP in packet:
            tcp_layer = packet[TCP]
            flags = tcp_layer.flags
            
            # Check each flag
            if flags & 0x02:  # SYN
                flow['tcp_flags']['SYN'] += 1
            if flags & 0x10:  # ACK
                flow['tcp_flags']['ACK'] += 1
            if flags & 0x01:  # FIN
                flow['tcp_flags']['FIN'] += 1
            if flags & 0x04:  # RST
                flow['tcp_flags']['RST'] += 1
            if flags & 0x08:  # PSH
                flow['tcp_flags']['PSH'] += 1
            if flags & 0x20:  # URG
                flow['tcp_flags']['URG'] += 1
        
        # Compute additional features
        self._add_cicddos_features(flow)
        self._add_suricata_features(flow)
        
        # Check if we have enough packets to analyze
        if flow['packets'] >= self.max_packets_per_flow and not flow['analyzed']:
            # Send flow to queue for analysis
            self._send_flow_to_queue(flow)
            flow['analyzed'] = True
        
        # Limit the flow table size
        if len(self.flow_table) > self.buffer_size:
            self._remove_oldest_flow()
    
    def _add_cicddos_features(self, flow):
        """
        Add features needed for the CIC-DDoS model.
        
        Args:
            flow: Flow data dictionary
        """
        # Basic features
        flow['ACK Flag Count'] = flow['tcp_flags']['ACK']
        flow['URG Flag Count'] = flow['tcp_flags']['URG']
        
        # Protocol as a numeric value
        if flow['protocol'] == 6:  # TCP
            flow['Protocol'] = 6
        elif flow['protocol'] == 17:  # UDP
            flow['Protocol'] = 17
        elif flow['protocol'] == 1 or flow['protocol'] == 58:  # ICMP or ICMPv6
            flow['Protocol'] = 1
        else:
            flow['Protocol'] = 0
        
        # Forward packet length features
        fwd_lengths = flow['packet_lengths']['forward']
        if fwd_lengths:
            flow['Fwd Packet Length Min'] = min(fwd_lengths)
            flow['Fwd Packet Length Max'] = max(fwd_lengths)
            if len(fwd_lengths) > 1:
                flow['Fwd Packet Length Std'] = np.std(fwd_lengths)
            else:
                flow['Fwd Packet Length Std'] = 0.0
        else:
            flow['Fwd Packet Length Min'] = 0
            flow['Fwd Packet Length Max'] = 0
            flow['Fwd Packet Length Std'] = 0.0
        
        # Init window bytes
        flow['Init Fwd Win Bytes'] = flow['init_win_bytes_forward']
        
        # Backward packet length features
        bwd_lengths = flow['packet_lengths']['backward']
        if bwd_lengths:
            flow['Bwd Packet Length Max'] = max(bwd_lengths)
        else:
            flow['Bwd Packet Length Max'] = 0
    
    def _add_suricata_features(self, flow):
        """
        Add features needed for the Suricata model.
        
        Args:
            flow: Flow data dictionary
        """
        # Basic features
        flow['src_port'] = flow['src_port'] if flow['src_port'] is not None else 0
        flow['dest_port'] = flow['dst_port'] if flow['dst_port'] is not None else 0
        
        # Byte and packet counts
        flow['bytes_toserver'] = flow['fwd_bytes']
        flow['bytes_toclient'] = flow['bwd_bytes']
        flow['pkts_toserver'] = flow['fwd_packets']
        flow['pkts_toclient'] = flow['bwd_packets']
        flow['total_bytes'] = flow['bytes']
        flow['total_pkts'] = flow['packets']
        
        # Average bytes per packet
        if flow['packets'] > 0:
            flow['avg_bytes_per_pkt'] = flow['bytes'] / flow['packets']
        else:
            flow['avg_bytes_per_pkt'] = 0
        
        # Byte and packet ratios
        if flow['bwd_bytes'] > 0:
            flow['bytes_ratio'] = flow['fwd_bytes'] / flow['bwd_bytes']
        else:
            flow['bytes_ratio'] = 1.0
            
        if flow['bwd_packets'] > 0:
            flow['pkts_ratio'] = flow['fwd_packets'] / flow['bwd_packets']
        else:
            flow['pkts_ratio'] = 1.0
        
        # Well-known port check
        flow['is_wellknown_port'] = 0
        if flow['src_port'] in self.wellknown_ports or flow['dst_port'] in self.wellknown_ports:
            flow['is_wellknown_port'] = 1
        
        # Protocol one-hot encoding
        for proto in ['tcp', 'udp', 'ipv6-icmp', 'icmp', 'ICMP', 'IPv6-ICMP', 'TCP', 'UDP']:
            flow[f'proto_{proto}'] = 0
        
        # Set the appropriate protocol
        if flow['protocol'] == 6:  # TCP
            flow['proto_tcp'] = 1
            flow['proto_TCP'] = 1
        elif flow['protocol'] == 17:  # UDP
            flow['proto_udp'] = 1
            flow['proto_UDP'] = 1
        elif flow['protocol'] == 1:  # ICMP
            flow['proto_icmp'] = 1
            flow['proto_ICMP'] = 1
        elif flow['protocol'] == 58:  # ICMPv6
            flow['proto_ipv6-icmp'] = 1
            flow['proto_IPv6-ICMP'] = 1
    
    def _send_flow_to_queue(self, flow):
        """
        Send a flow to the analysis queue.
        
        Args:
            flow: Flow data dictionary
        """
        try:
            # Create a copy to avoid modification issues
            flow_copy = flow.copy()
            
            # Add packet rate
            duration = flow_copy['last_time'] - flow_copy['start_time']
            if duration > 0:
                flow_copy['packet_rate'] = flow_copy['packets'] / duration
                flow_copy['byte_rate'] = flow_copy['bytes'] / duration
            else:
                flow_copy['packet_rate'] = 0
                flow_copy['byte_rate'] = 0
            
            # Put in queue
            self.packet_queue.put(flow_copy)
            
        except Exception as e:
            self.logger.error(f"Error sending flow to queue: {e}", exc_info=True)
    
    def _remove_oldest_flow(self):
        """Remove the oldest flow from the flow table."""
        oldest_time = float('inf')
        oldest_key = None
        
        # Find the oldest flow
        for key, time_val in self.flow_expiry.items():
            if time_val < oldest_time:
                oldest_time = time_val
                oldest_key = key
        
        # Remove the flow
        if oldest_key:
            if oldest_key in self.flow_table:
                del self.flow_table[oldest_key]
            if oldest_key in self.flow_expiry:
                del self.flow_expiry[oldest_key]
            
            self.stats['current_flows'] -= 1
    
    def _cleanup_old_flows(self, timeout=60):
        """
        Thread function to clean up old flows.
        
        Args:
            timeout: Flow timeout in seconds
        """
        while self.running:
            try:
                with self.lock:
                    current_time = time.time()
                    expired_keys = []
                    
                    # Find expired flows
                    for key, last_time in self.flow_expiry.items():
                        if current_time - last_time > timeout:
                            expired_keys.append(key)
                    
                    # Process expired flows
                    for key in expired_keys:
                        # Send flow for analysis if it has not been analyzed yet
                        if key in self.flow_table and not self.flow_table[key]['analyzed']:
                            self._send_flow_to_queue(self.flow_table[key])
                        
                        # Remove from tables
                        if key in self.flow_table:
                            del self.flow_table[key]
                        if key in self.flow_expiry:
                            del self.flow_expiry[key]
                        
                                                # Update stats
                        self.stats['current_flows'] -= 1
                        self.stats['expired_flows'] += 1
                
            except Exception as e:
                self.logger.error(f"Error cleaning up old flows: {e}", exc_info=True)
            
            # Sleep for a while
            time.sleep(10)
    
    def get_stats(self):
        """
        Get packet capture statistics.
        
        Returns:
            Dict with statistics
        """
        with self.lock:
            # Calculate derived stats
            uptime = time.time() - self.stats['start_time'] if self.stats['start_time'] > 0 else 0
            packets_per_second = self.stats['total_packets'] / uptime if uptime > 0 else 0
            
            stats = self.stats.copy()
            stats['uptime'] = uptime
            stats['packets_per_second'] = packets_per_second
            
            return stats