import queue
import threading
import time
from typing import List, Dict, Any, Optional
import numpy as np
import pyshark

class PacketCapture:
    def __init__(self, interface: str, packet_queue: queue.Queue,
                 capture_filter: Optional[str] = None, buffer_size: int = 1000, max_packets_per_flow: int = 20):
        self.interface = interface
        self.packet_queue = packet_queue
        self.capture_filter = capture_filter
        self.buffer_size = buffer_size
        self.max_packets_per_flow = max_packets_per_flow
        self.running = False
        self.capture_thread = None
        self.lock = threading.Lock()
        self.flow_dict: Dict[str, Dict[str, Any]] = {}

    def start_capture(self):
        self.running = True
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def stop_capture(self):
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)

    def _capture_packets(self):
        try:
            capture = pyshark.LiveCapture(
                interface=self.interface,
                bpf_filter="tcp",  # BPF đơn giản, không bị lỗi liên quan đến parser
                use_json=True
            )
            for packet in capture.sniff_continuously():
                if not self.running:
                    break
                flow_data = self._process_packet(packet)
                if flow_data and self.packet_queue.qsize() < self.buffer_size:
                    self.packet_queue.put(flow_data)
                if time.time() % 60 < 1:
                    self._clean_old_flows()
        except Exception as e:
            print(f"Lỗi khi bắt gói tin: {e}")

    def _process_packet(self, packet):
        """
        Xử lý một gói tin và thêm nó vào luồng tương ứng.
        
        Args:
            packet: Gói tin Scapy để xử lý
        """
        try:
            # Kiểm tra xem gói tin có chứa IP layer không
            if 'IP' not in packet:
                return
            
            # Trích xuất thông tin IP
            ip_layer = packet['IP']
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            protocol = None
            
            # Trích xuất thông tin giao thức
            if 'TCP' in packet:
                protocol = 'tcp'
                tcp_layer = packet['TCP']
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-tcp"
                
                # Xử lý gói TCP
                self._process_tcp_packet(packet, flow_key)
                
            elif 'UDP' in packet:
                protocol = 'udp'
                udp_layer = packet['UDP']
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                flow_key = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}-udp"
                
                # Xử lý gói UDP
                self._process_udp_packet(packet, flow_key)
                
            elif 'ICMP' in packet:
                protocol = 'icmp'
                # ICMP không có port, sử dụng 0 để thống nhất
                src_port = 0
                dst_port = 0
                flow_key = f"{src_ip}:0-{dst_ip}:0-icmp"
                
                # Xử lý gói ICMP
                self._process_icmp_packet(packet, flow_key)
                
            else:
                # Các giao thức khác không được hỗ trợ
                return
            
            # Lấy thời gian gói tin
            timestamp = packet.time
            
            # Kiểm tra xem luồng đã tồn tại chưa
            if flow_key not in self.flow_table:
                # Tạo mới luồng
                flow = {
                    'flow_key': flow_key,
                    'start_time': timestamp,
                    'last_update': timestamp,
                    'packet_count': 1,
                    'byte_count': len(packet),
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'fwd_bytes': len(packet),
                    'bwd_bytes': 0,
                    'fwd_packets': 1,
                    'bwd_packets': 0,
                    'packet_lengths': {'forward': [len(packet)], 'backward': []},
                    'tcp_flags': {},
                    'flow_duration': 0,
                    'flow_rate': 0,
                    'packet_rate': 0,
                    'byte_rate': 0
                }
                
                # Lưu thông tin cửa sổ TCP nếu là gói TCP
                if protocol == 'tcp' and hasattr(packet['TCP'], 'window'):
                    flow['init_win_bytes_forward'] = packet['TCP'].window
                    flow['init_win_bytes_backward'] = 0
                else:
                    flow['init_win_bytes_forward'] = 0
                    flow['init_win_bytes_backward'] = 0
                
                # Thiết lập các giá trị cho Suricata features
                flow['bytes_toserver'] = flow['fwd_bytes']
                flow['bytes_toclient'] = flow['bwd_bytes']
                flow['pkts_toserver'] = flow['fwd_packets']
                flow['pkts_toclient'] = flow['bwd_packets']
                
                # Thêm các đặc trưng cần thiết cho mô hình CIC-DDoS
                self._add_cicddos_features(flow)
                
                # Thêm các đặc trưng cần thiết cho mô hình Suricata
                self._add_suricata_features(flow)
                
                # Lưu luồng vào bảng
                self.flow_table[flow_key] = flow
                
            else:
                # Cập nhật luồng đã tồn tại
                flow = self.flow_table[flow_key]
                flow['last_update'] = timestamp
                flow['packet_count'] += 1
                flow['byte_count'] += len(packet)
                
                # Xác định hướng gói tin
                is_forward = (src_ip == flow['src_ip'] and src_port == flow['src_port'])
                
                if is_forward:
                    flow['fwd_bytes'] += len(packet)
                    flow['fwd_packets'] += 1
                    flow['bytes_toserver'] = flow['fwd_bytes']
                    flow['pkts_toserver'] = flow['fwd_packets']
                    
                    if 'packet_lengths' not in flow:
                        flow['packet_lengths'] = {'forward': [], 'backward': []}
                    if 'forward' not in flow['packet_lengths']:
                        flow['packet_lengths']['forward'] = []
                    
                    flow['packet_lengths']['forward'].append(len(packet))
                else:
                    flow['bwd_bytes'] += len(packet)
                    flow['bwd_packets'] += 1
                    flow['bytes_toclient'] = flow['bwd_bytes']
                    flow['pkts_toclient'] = flow['bwd_packets']
                    
                    if 'packet_lengths' not in flow:
                        flow['packet_lengths'] = {'forward': [], 'backward': []}
                    if 'backward' not in flow['packet_lengths']:
                        flow['packet_lengths']['backward'] = []
                    
                    flow['packet_lengths']['backward'].append(len(packet))
                    
                    # Lưu thông tin về cửa sổ ngược nếu đây là gói TCP
                    if protocol == 'tcp' and hasattr(packet['TCP'], 'window') and flow.get('init_win_bytes_backward', 0) == 0:
                        flow['init_win_bytes_backward'] = packet['TCP'].window
                
                # Cập nhật thông tin TCP flags nếu là gói TCP
                if protocol == 'tcp' and hasattr(packet['TCP'], 'flags'):
                    flags = packet['TCP'].flags
                    
                    if 'tcp_flags' not in flow:
                        flow['tcp_flags'] = {}
                    
                    # ACK flag
                    if flags & 0x10:  # 0x10 là bit ACK
                        flow['tcp_flags']['ACK'] = flow['tcp_flags'].get('ACK', 0) + 1
                    
                    # URG flag
                    if flags & 0x20:  # 0x20 là bit URG
                        flow['tcp_flags']['URG'] = flow['tcp_flags'].get('URG', 0) + 1
                    
                    # Các flag khác nếu cần
                    if flags & 0x02:  # SYN flag
                        flow['tcp_flags']['SYN'] = flow['tcp_flags'].get('SYN', 0) + 1
                    
                    if flags & 0x01:  # FIN flag
                        flow['tcp_flags']['FIN'] = flow['tcp_flags'].get('FIN', 0) + 1
                    
                    if flags & 0x04:  # RST flag
                        flow['tcp_flags']['RST'] = flow['tcp_flags'].get('RST', 0) + 1
                    
                    if flags & 0x08:  # PSH flag
                        flow['tcp_flags']['PSH'] = flow['tcp_flags'].get('PSH', 0) + 1
                
                # Tính toán các đặc trưng liên quan đến thời gian và tốc độ
                flow_duration = timestamp - flow['start_time']
                if flow_duration > 0:
                    flow['flow_duration'] = flow_duration
                    flow['flow_rate'] = 1.0 / flow_duration
                    flow['packet_rate'] = flow['packet_count'] / flow_duration
                    flow['byte_rate'] = flow['byte_count'] / flow_duration
                
                # Thêm các đặc trưng cần thiết cho mô hình CIC-DDoS
                self._add_cicddos_features(flow)
                
                # Thêm các đặc trưng cần thiết cho mô hình Suricata
                self._add_suricata_features(flow)
                
                # Cập nhật luồng vào bảng
                self.flow_table[flow_key] = flow
            
            # Kiểm tra nếu đã đủ số lượng gói tin để phân tích luồng
            if self.flow_packet_threshold > 0 and flow['packet_count'] >= self.flow_packet_threshold:
                # Gửi luồng đến hàng đợi để phân tích
                self._send_flow_to_queue(flow)
                
                # Đặt lại bộ đếm gói tin
                flow['packet_count'] = 0
                
                # Ghi log nếu debug
                self.logger.debug(f"Đã gửi luồng {flow_key} để phân tích")
        
        except Exception as e:
            self.logger.error(f"Lỗi khi process_packet: {e}", exc_info=True)

    def _process_tcp_packet(self, packet, flow_key):
        """
        Xử lý một gói tin TCP và cập nhật thông tin cho luồng tương ứng.
        
        Args:
            packet: Gói tin TCP
            flow_key: Khóa của luồng
        """
        try:
            # Phương thức này sẽ được gọi từ _process_packet
            # và các xử lý cụ thể cho TCP đã được thực hiện trong _process_packet
            pass
        except Exception as e:
            self.logger.error(f"Lỗi khi xử lý gói TCP: {e}", exc_info=True)

    def _process_udp_packet(self, packet, flow_key):
        """
        Xử lý một gói tin UDP và cập nhật thông tin cho luồng tương ứng.
        
        Args:
            packet: Gói tin UDP
            flow_key: Khóa của luồng
        """
        try:
            # Phương thức này sẽ được gọi từ _process_packet
            # và các xử lý cụ thể cho UDP đã được thực hiện trong _process_packet
            pass
        except Exception as e:
            self.logger.error(f"Lỗi khi xử lý gói UDP: {e}", exc_info=True)

    def _process_icmp_packet(self, packet, flow_key):
        """
        Xử lý một gói tin ICMP và cập nhật thông tin cho luồng tương ứng.
        
        Args:
            packet: Gói tin ICMP
            flow_key: Khóa của luồng
        """
        try:
            # Xử lý đặc biệt cho ICMP nếu cần
            # Hiện tại, các xử lý cơ bản đã được thực hiện trong _process_packet
            pass
        except Exception as e:
            self.logger.error(f"Lỗi khi xử lý gói ICMP: {e}", exc_info=True)

    def _clean_old_flows(self, timeout=60):
        now = time.time()
        to_delete = []
        with self.lock:
            for key, flow in self.flow_dict.items():
                if now - flow["Flow Start Time"] > timeout:
                    to_delete.append(key)
            for key in to_delete:
                del self.flow_dict[key]

    def _add_cicddos_features(self, flow):
        """
        Thêm các đặc trưng cần thiết cho mô hình CIC-DDoS.
        
        Args:
            flow: Dict chứa thông tin luồng
        """
        # Đảm bảo các cấu trúc dữ liệu cần thiết tồn tại
        if 'tcp_flags' not in flow:
            flow['tcp_flags'] = {}
        
        if 'packet_lengths' not in flow:
            flow['packet_lengths'] = {'forward': [], 'backward': []}
        
        # Đảm bảo các đặc trưng cụ thể tồn tại
        if 'init_win_bytes_forward' not in flow:
            flow['init_win_bytes_forward'] = 0
        
        # Tính toán Fwd Packet Length Std nếu chưa có
        if 'packet_lengths' in flow and 'forward' in flow['packet_lengths'] and len(flow['packet_lengths']['forward']) > 1:
            import numpy as np
            flow['fwd_pkt_len_std'] = np.std(flow['packet_lengths']['forward'])
        else:
            flow['fwd_pkt_len_std'] = 0

    def _add_suricata_features(self, flow):
        """
        Thêm các đặc trưng cần thiết cho mô hình Suricata.
        
        Args:
            flow: Dict chứa thông tin luồng
        """
        # Đảm bảo các đặc trưng Suricata cụ thể tồn tại
        if 'bytes_toserver' not in flow and 'fwd_bytes' in flow:
            flow['bytes_toserver'] = flow['fwd_bytes']
        
        if 'bytes_toclient' not in flow and 'bwd_bytes' in flow:
            flow['bytes_toclient'] = flow['bwd_bytes']
        
        if 'pkts_toserver' not in flow and 'fwd_packets' in flow:
            flow['pkts_toserver'] = flow['fwd_packets']
        
        if 'pkts_toclient' not in flow and 'bwd_packets' in flow:
            flow['pkts_toclient'] = flow['bwd_packets']
        
        # Tính toán tổng và tỷ lệ
        bytes_toserver = flow.get('bytes_toserver', 0)
        bytes_toclient = flow.get('bytes_toclient', 0)
        pkts_toserver = flow.get('pkts_toserver', 0)
        pkts_toclient = flow.get('pkts_toclient', 0)
        
        flow['total_bytes'] = bytes_toserver + bytes_toclient
        flow['total_pkts'] = pkts_toserver + pkts_toclient
        
        # Tránh chia cho 0
        if flow['total_pkts'] > 0:
            flow['avg_bytes_per_pkt'] = flow['total_bytes'] / flow['total_pkts']
        else:
            flow['avg_bytes_per_pkt'] = 0
            
        if bytes_toclient > 0:
            flow['bytes_ratio'] = bytes_toserver / bytes_toclient
        else:
            flow['bytes_ratio'] = bytes_toserver if bytes_toserver > 0 else 1
            
        if pkts_toclient > 0:
            flow['pkts_ratio'] = pkts_toserver / pkts_toclient
        else:
            flow['pkts_ratio'] = pkts_toserver if pkts_toserver > 0 else 1
        
        # Kiểm tra cổng phổ biến
        src_port = flow.get('src_port', 0)
        dst_port = flow.get('dst_port', 0)
        flow['is_wellknown_port'] = 1 if (src_port < 1024 or dst_port < 1024) else 0
        
        # Mã hóa one-hot cho giao thức
        protocol = flow.get('protocol', 'tcp').lower()
        for proto in ['tcp', 'udp', 'ipv6-icmp', 'icmp']:
            flow[f'proto_{proto}'] = 1 if proto == protocol else 0
            flow[f'proto_{proto.upper()}'] = 1 if proto == protocol else 0