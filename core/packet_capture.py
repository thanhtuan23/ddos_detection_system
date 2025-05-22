# src/ddos_detection_system/core/packet_capture.py
import pyshark
import queue
import threading
import time
from typing import List, Dict, Any, Optional
# Thay thế import pyshark với:
from scapy.all import sniff, IP, TCP, UDP

class PacketCapture:
    """Thu thập gói tin và phân tích luồng mạng thời gian thực."""
    
    def __init__(self, interface: str, packet_queue: queue.Queue, 
                 capture_filter: Optional[str] = None, buffer_size: int = 1000):
        """
        Khởi tạo module thu thập gói tin.
        
        Args:
            interface: Giao diện mạng để bắt gói tin
            packet_queue: Queue để đẩy các gói tin đã thu thập
            capture_filter: Bộ lọc BPF để áp dụng vào việc bắt gói tin
            buffer_size: Kích thước bộ đệm cho các gói tin đã bắt
        """
        self.interface = interface
        self.packet_queue = packet_queue
        self.capture_filter = capture_filter
        self.buffer_size = buffer_size
        self.running = False
        self.capture_thread = None
        self.flow_stats = {}  # Lưu trữ các thống kê về luồng
        self.mssql_traffic_stats: Dict[str, Dict[str, Any]] = {}

    def start_capture(self):
        """Bắt đầu thu thập gói tin trong một thread riêng biệt."""
        self.running = True
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
    def stop_capture(self):
        """Dừng quá trình thu thập gói tin."""
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)
            
    def _capture_packets(self):
        """Thực hiện thu thập gói tin và đưa vào hàng đợi."""
        try:
            # Sử dụng pyshark để bắt gói tin thời gian thực
            capture = pyshark.LiveCapture(interface=self.interface, 
                                          display_filter=self.capture_filter)
            
            for packet in capture.sniff_continuously():
                if not self.running:
                    break
                    
                # Xử lý gói tin và cập nhật thống kê luồng
                flow_data = self._process_packet(packet)
                
                if flow_data:
                    # Đưa dữ liệu luồng vào hàng đợi để phân tích
                    if self.packet_queue.qsize() < self.buffer_size:
                        self.packet_queue.put(flow_data)
                        
        except Exception as e:
            print(f"Lỗi khi bắt gói tin: {e}")
            
    def _process_packet(self, packet) -> Optional[Dict[str, Any]]:
        """
        Xử lý gói tin riêng lẻ và cập nhật thống kê luồng, bao gồm nhận diện MSSQL traffic.
        """
        try:
            if 'ip' in packet:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                protocol = packet.transport_layer if hasattr(packet, 'transport_layer') else 'Unknown'

                if protocol == 'TCP' and hasattr(packet, 'tcp'):
                    src_port = int(packet.tcp.srcport)
                    dst_port = int(packet.tcp.dstport)
                    flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-TCP"

                    # Nhận diện traffic MSSQL qua cổng 1433
                    is_mssql_traffic = src_port == 1433 or dst_port == 1433

                    if flow_key not in self.flow_stats:
                        self.flow_stats[flow_key] = {
                            'start_time': time.time(),
                            'packet_count': 0,
                            'byte_count': 0,
                            'syn_count': 0,
                            'fin_count': 0,
                            'rst_count': 0,
                            'psh_count': 0,
                            'ack_count': 0,
                            'urg_count': 0,
                            'packet_sizes': [],
                            'is_mssql_traffic': is_mssql_traffic
                        }

                    stats = self.flow_stats[flow_key]
                    stats['packet_count'] += 1
                    stats['byte_count'] += int(packet.length)
                    stats['packet_sizes'].append(int(packet.length))

                    # Cập nhật các cờ TCP nếu có
                    if hasattr(packet.tcp, 'flags'):
                        flags = int(packet.tcp.flags, 16)
                        if flags & 0x02:  # SYN
                            stats['syn_count'] += 1
                        if flags & 0x01:  # FIN
                            stats['fin_count'] += 1
                        if flags & 0x04:  # RST
                            stats['rst_count'] += 1
                        if flags & 0x08:  # PSH
                            stats['psh_count'] += 1
                        if flags & 0x10:  # ACK
                            stats['ack_count'] += 1
                        if flags & 0x20:  # URG
                            stats['urg_count'] += 1

                    if stats['packet_count'] >= 10:
                        flow_features = self._calculate_flow_features(flow_key)
                        if len(self.flow_stats) > 1000:
                            self._clean_old_flows()
                        return flow_features

                elif protocol == 'UDP' and hasattr(packet, 'udp'):
                    src_port = int(packet.udp.srcport)
                    dst_port = int(packet.udp.dstport)
                    flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-UDP"

                    if flow_key not in self.flow_stats:
                        self.flow_stats[flow_key] = {
                            'start_time': time.time(),
                            'packet_count': 0,
                            'byte_count': 0,
                            'packet_sizes': []
                        }

                    stats = self.flow_stats[flow_key]
                    stats['packet_count'] += 1
                    stats['byte_count'] += int(packet.length)
                    stats['packet_sizes'].append(int(packet.length))

                    if stats['packet_count'] >= 10:
                        flow_features = self._calculate_flow_features(flow_key)
                        if len(self.flow_stats) > 1000:
                            self._clean_old_flows()
                        return flow_features
            return None
        except Exception as e:
            print(f"Lỗi khi xử lý gói tin: {e}")
            return None

    def _calculate_flow_features(self, flow_key: str) -> Dict[str, Any]:
        """
        Tính toán các đặc trưng luồng từ các gói tin đã thu thập.
        
        Args:
            flow_key: Khóa nhận diện luồng
            
        Returns:
            Dict chứa các đặc trưng luồng cho mô hình ML
        """
        stats = self.flow_stats[flow_key]
        current_time = time.time()
        duration = current_time - stats['start_time']
        
        features = {
            'Flow Key': flow_key,
            'Protocol': flow_key.split('-')[-1],
            'Flow Duration': duration,
            'Total Packets': stats['packet_count'],
            'Total Bytes': stats['byte_count'],
            'Packet Rate': stats['packet_count'] / duration if duration > 0 else 0,
            'Byte Rate': stats['byte_count'] / duration if duration > 0 else 0,
            'Packet Length Mean': sum(stats['packet_sizes']) / len(stats['packet_sizes']) if stats['packet_sizes'] else 0,
            'Packet Length Std': self._calculate_std(stats['packet_sizes']),
            'Packet Length Min': min(stats['packet_sizes']) if stats['packet_sizes'] else 0,
            'Packet Length Max': max(stats['packet_sizes']) if stats['packet_sizes'] else 0
        }
        
        # Thêm các đặc trưng đặc biệt cho TCP
        if 'TCP' in flow_key:
            features.update({
                'SYN Flag Count': stats['syn_count'],
                'FIN Flag Count': stats['fin_count'],
                'RST Flag Count': stats['rst_count'],
                'PSH Flag Count': stats['psh_count'],
                'ACK Flag Count': stats['ack_count'],
                'URG Flag Count': stats['urg_count'],
                'SYN Flag Rate': stats['syn_count'] / stats['packet_count'] if stats['packet_count'] > 0 else 0,
                'ACK Flag Rate': stats['ack_count'] / stats['packet_count'] if stats['packet_count'] > 0 else 0
            })
        
        return features
    
    def _calculate_std(self, values: List[int]) -> float:
        """Tính độ lệch chuẩn của một danh sách giá trị."""
        if not values or len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return variance ** 0.5
    
    def _clean_old_flows(self):
        """Xóa các luồng cũ để giải phóng bộ nhớ."""
        current_time = time.time()
        old_flows = []
        
        for flow_key, stats in self.flow_stats.items():
            if current_time - stats['start_time'] > 60:  # Xóa các luồng cũ hơn 60 giây
                old_flows.append(flow_key)
        
        for flow_key in old_flows:
            del self.flow_stats[flow_key]