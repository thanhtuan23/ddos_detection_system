import queue
import threading
import time
from typing import List, Dict, Any, Optional
import pyshark

class PacketCapture:
    """Thu thập gói tin và phân tích luồng mạng thời gian thực."""

    def __init__(self, interface: str, packet_queue: queue.Queue,
                 capture_filter: Optional[str] = None, buffer_size: int = 1000, max_packets_per_flow: int = 20):
        """
        Args:
            interface: Giao diện mạng để bắt gói tin
            packet_queue: Queue để đẩy các flow đã thu thập
            capture_filter: Bộ lọc BPF cho việc bắt gói tin
            buffer_size: Kích thước queue tối đa
            max_packets_per_flow: Số gói tối đa mỗi flow trước khi push vào queue
        """
        self.interface = interface
        self.packet_queue = packet_queue
        self.capture_filter = capture_filter
        self.buffer_size = buffer_size
        self.max_packets_per_flow = max_packets_per_flow
        self.running = False
        self.capture_thread = None
        self.lock = threading.Lock()
        # Lưu các flow đang gom packet
        self.flow_dict: Dict[str, Dict[str, Any]] = {}

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
        """Thu thập packet, gom thành flow rồi put vào queue khi đủ điều kiện."""
        try:
            capture = pyshark.LiveCapture(
                interface=self.interface,
                display_filter=self.capture_filter
            )
            for packet in capture.sniff_continuously():
                if not self.running:
                    break
                flow_data = self._process_packet(packet)
                # flow_data chỉ trả về khi đã đủ số packet trong 1 flow
                if flow_data and self.packet_queue.qsize() < self.buffer_size:
                    self.packet_queue.put(flow_data)
                # Option: dọn flow cũ định kỳ để tránh leak
                if time.time() % 60 < 1:
                    self._clean_old_flows()
        except Exception as e:
            print(f"Lỗi khi bắt gói tin: {e}")

    def _process_packet(self, pkt):
        """Gom packet thành flow, return flow khi đủ điều kiện."""
        def safe_flag_to_int(flag):
            # Chuyển các giá trị 'True', 'False', True, False, 1, 0 về 1/0
            if isinstance(flag, bool):
                return int(flag)
            if isinstance(flag, int):
                return flag
            if isinstance(flag, str):
                if flag.lower() == "true":
                    return 1
                if flag.lower() == "false":
                    return 0
                try:
                    return int(flag)
                except Exception:
                    return 0
            return 0

        try:
            # Ưu tiên bắt đúng thứ tự giao thức!
            if hasattr(pkt, 'udp'):
                proto = 'UDP'
            elif hasattr(pkt, 'tcp'):
                proto = 'TCP'
            elif hasattr(pkt, 'icmp'):
                proto = 'ICMP'
            else:
                proto = 'Unknown'
            timestamp = float(pkt.sniff_time.timestamp())
            length = int(pkt.length)

            # Chỉ xử lý IP/TCP/UDP
            if not hasattr(pkt, 'ip'):
                return None
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst

            if proto == "TCP" and hasattr(pkt, 'tcp'):
                src_port, dst_port = pkt.tcp.srcport, pkt.tcp.dstport
            elif proto == "UDP" and hasattr(pkt, 'udp'):
                src_port, dst_port = pkt.udp.srcport, pkt.udp.dstport
            else:
                src_port = dst_port = 0

            # Tạo key cho flow
            flow_key = f"{src_ip}-{dst_ip}:{dst_port}"

            with self.lock:
                flow = self.flow_dict.setdefault(flow_key, {
                    "Packet Lengths": [],
                    "Packet Times": [],
                    "SYN Flag Count": 0,
                    "FIN Flag Count": 0,
                    "RST Flag Count": 0,
                    "PSH Flag Count": 0,
                    "ACK Flag Count": 0,
                    "URG Flag Count": 0,
                    "Flow Start Time": 0,
                    "Protocol": proto,
                    "Source IP": src_ip,
                    "Destination IP": dst_ip,
                    "Source Port": int(src_port) if src_port else 0,
                    "Destination Port": int(dst_port) if dst_port else 0,
                })
                if flow["Flow Start Time"] == 0:
                    flow["Flow Start Time"] = timestamp
                flow["Packet Lengths"].append(length)
                flow["Packet Times"].append(timestamp)

                if proto == "TCP" and hasattr(pkt, 'tcp'):
                    tcp = pkt.tcp
                    if safe_flag_to_int(getattr(tcp, "flags_syn", 0)): flow["SYN Flag Count"] += 1
                    if safe_flag_to_int(getattr(tcp, "flags_fin", 0)): flow["FIN Flag Count"] += 1
                    if safe_flag_to_int(getattr(tcp, "flags_rst", 0)): flow["RST Flag Count"] += 1
                    if safe_flag_to_int(getattr(tcp, "flags_psh", 0)): flow["PSH Flag Count"] += 1
                    if safe_flag_to_int(getattr(tcp, "flags_ack", 0)): flow["ACK Flag Count"] += 1
                    if safe_flag_to_int(getattr(tcp, "flags_urg", 0)): flow["URG Flag Count"] += 1

                # Khi đạt số lượng gói, push flow vào queue để detection xử lý
                if len(flow["Packet Lengths"]) >= self.max_packets_per_flow:
                    flow_summary = dict(flow)  # Copy dữ liệu
                    flow_summary["Flow Key"] = flow_key
                    flow_summary["Flow Duration"] = (
                        flow["Packet Times"][-1] - flow["Packet Times"][0]
                        if len(flow["Packet Times"]) > 1 else 0
                    )
                    flow_summary["Total Bytes"] = sum(flow["Packet Lengths"])
                    flow_summary["Total Packets"] = len(flow["Packet Lengths"])
                    duration = flow_summary["Flow Duration"]
                    flow_summary["Packet Rate"] = flow_summary["Total Packets"] / duration if duration > 0 else 0
                    flow_summary["Byte Rate"] = flow_summary["Total Bytes"] / duration if duration > 0 else 0

                    del self.flow_dict[flow_key]
                    print(
                        f"[DEBUG] PUSH FLOW: {flow_key}, packets: {flow_summary['Total Packets']}, bytes: {flow_summary['Total Bytes']}, rate: {flow_summary['Packet Rate']:.2f}, proto: {proto}"
                    )
                    return flow_summary

            # Print từng packet nếu muốn debug chi tiết hơn:
            print(f"Captured packet: proto={proto}, src={src_ip}, dst={dst_ip}, len={length}")

        except Exception as e:
            print(f"[Capture] Lỗi khi process_packet: {e}")
        return None

    def _clean_old_flows(self, timeout=60):
        """Xóa các flow chưa đủ packet nhưng đã quá cũ để giải phóng bộ nhớ."""
        now = time.time()
        to_delete = []
        with self.lock:
            for key, flow in self.flow_dict.items():
                if now - flow["Flow Start Time"] > timeout:
                    to_delete.append(key)
            for key in to_delete:
                del self.flow_dict[key]

    # def _calculate_flow_features(self, flow_key: str) -> Dict[str, Any]:
    #     """
    #     Tính toán các đặc trưng luồng từ các gói tin đã thu thập.
        
    #     Args:
    #         flow_key: Khóa nhận diện luồng
            
    #     Returns:
    #         Dict chứa các đặc trưng luồng cho mô hình ML
    #     """
    #     stats = self.flow_stats[flow_key]
    #     parts = flow_key.split('-')
    #     current_time = time.time()
    #     src_dst = parts[0].split(':')
    #     duration = current_time - stats['start_time']
        
    #     features = {
    #         'Flow Key': flow_key,
    #         'Source IP': src_dst[0],
    #         'Destination IP': src_dst[1],
    #         'Protocol': parts[-1],
    #         'Flow Duration': duration,
    #         'Total Packets': stats['packet_count'],
    #         'Total Bytes': stats['byte_count'],
    #         'Packet Rate': stats['packet_count'] / duration if duration > 0 else 0,
    #         'Byte Rate': stats['byte_count'] / duration if duration > 0 else 0,
    #         'Packet Length Mean': sum(stats['packet_sizes']) / len(stats['packet_sizes']) if stats['packet_sizes'] else 0,
    #         'Packet Length Std': self._calculate_std(stats['packet_sizes']),
    #         'Packet Length Min': min(stats['packet_sizes']) if stats['packet_sizes'] else 0,
    #         'Packet Length Max': max(stats['packet_sizes']) if stats['packet_sizes'] else 0,
    #         'Source Port': stats.get('Source Port', 0),
    #         'Destination Port': stats.get('Destination Port', 0),
    #         'Packet Times': stats.get('Packet Times', [])
    #     }
        
    #     # Thêm các đặc trưng đặc biệt cho TCP
    #     if 'TCP' in flow_key:
    #         features.update({
    #             'SYN Flag Count': stats['syn_count'],
    #             'FIN Flag Count': stats['fin_count'],
    #             'RST Flag Count': stats['rst_count'],
    #             'PSH Flag Count': stats['psh_count'],
    #             'ACK Flag Count': stats['ack_count'],
    #             'URG Flag Count': stats['urg_count'],
    #             'SYN Flag Rate': stats['syn_count'] / stats['packet_count'] if stats['packet_count'] > 0 else 0,
    #             'ACK Flag Rate': stats['ack_count'] / stats['packet_count'] if stats['packet_count'] > 0 else 0
    #         })
        
    #     return features
    
    # def _calculate_std(self, values: List[int]) -> float:
    #     """Tính độ lệch chuẩn của một danh sách giá trị."""
    #     if not values or len(values) < 2:
    #         return 0.0
    #     mean = sum(values) / len(values)
    #     variance = sum((x - mean) ** 2 for x in values) / len(values)
    #     return variance ** 0.5
    