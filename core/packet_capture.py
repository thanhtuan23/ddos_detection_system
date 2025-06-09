import queue
import threading
import time
from typing import List, Dict, Any, Optional
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

    def _process_packet(self, pkt):
        try:
            if hasattr(pkt, 'udp'): proto = 'UDP'
            elif hasattr(pkt, 'tcp'): proto = 'TCP'
            elif hasattr(pkt, 'icmp'): proto = 'ICMP'
            else: proto = 'Unknown'

            timestamp = float(pkt.sniff_time.timestamp())
            length = int(pkt.length)
            if not hasattr(pkt, 'ip'):
                return None
            src_ip, dst_ip = pkt.ip.src, pkt.ip.dst

            src_port = dst_port = 0
            if proto == "TCP" and hasattr(pkt, 'tcp'):
                src_port, dst_port = pkt.tcp.srcport, pkt.tcp.dstport
            elif proto == "UDP" and hasattr(pkt, 'udp'):
                src_port, dst_port = pkt.udp.srcport, pkt.udp.dstport

            flow_key = f"{src_ip}-{dst_ip}:{dst_port}"

            with self.lock:
                flow = self.flow_dict.setdefault(flow_key, {
                    "Packet Lengths": [], "Packet Times": [],
                    "SYN Flag Count": 0, "FIN Flag Count": 0, "RST Flag Count": 0,
                    "PSH Flag Count": 0, "ACK Flag Count": 0, "URG Flag Count": 0,
                    "Flow Start Time": 0, "Protocol": proto, "Source IP": src_ip,
                    "Destination IP": dst_ip, "Source Port": int(src_port) if src_port else 0,
                    "Destination Port": int(dst_port) if dst_port else 0,
                })
                if flow["Flow Start Time"] == 0:
                    flow["Flow Start Time"] = timestamp
                flow["Packet Lengths"].append(length)
                flow["Packet Times"].append(timestamp)

                if proto == "TCP" and hasattr(pkt, 'tcp') and hasattr(pkt.tcp, "flags"):
                    try:
                        flags = int(pkt.tcp.flags, 16)
                        if flags & 0x02: flow["SYN Flag Count"] += 1  # SYN
                        if flags & 0x01: flow["FIN Flag Count"] += 1  # FIN
                        if flags & 0x04: flow["RST Flag Count"] += 1  # RST
                        if flags & 0x08: flow["PSH Flag Count"] += 1  # PSH
                        if flags & 0x10: flow["ACK Flag Count"] += 1  # ACK
                        if flags & 0x20: flow["URG Flag Count"] += 1  # URG
                    except Exception as e:
                        print(f"[WARN] Không parse được flags: {e}")

                if len(flow["Packet Lengths"]) >= self.max_packets_per_flow:
                    flow_summary = dict(flow)
                    flow_summary["Flow Key"] = flow_key
                    flow_summary["Flow Duration"] = (
                        flow["Packet Times"][-1] - flow["Packet Times"][0] if len(flow["Packet Times"]) > 1 else 0
                    )
                    flow_summary["Total Bytes"] = sum(flow["Packet Lengths"])
                    flow_summary["Total Packets"] = len(flow["Packet Lengths"])
                    duration = flow_summary["Flow Duration"]
                    flow_summary["Packet Rate"] = flow_summary["Total Packets"] / duration if duration > 0 else 0
                    flow_summary["Byte Rate"] = flow_summary["Total Bytes"] / duration if duration > 0 else 0

                    # Gán nhãn đơn giản
                    proto_num = {'ICMP': 1, 'UDP': 17, 'TCP': 6}.get(proto, 0)
                    flow_summary["Protocol"] = proto_num
                    if proto == 'TCP' and flow["SYN Flag Count"] > 10 and flow["ACK Flag Count"] == 0:
                        flow_summary["Label"] = "Syn"
                    elif proto == 'TCP' and flow["ACK Flag Count"] > 20 and flow["SYN Flag Count"] == 0:
                        flow_summary["Label"] = "ACK"
                    elif proto == 'UDP':
                        flow_summary["Label"] = "UDP"
                    elif proto == 'ICMP':
                        flow_summary["Label"] = "ICMP"
                    else:
                        flow_summary["Label"] = "Benign"

                    del self.flow_dict[flow_key]
                    return flow_summary

            print(f"Captured packet: proto={proto}, src={src_ip}, dst={dst_ip}, len={length}")

        except Exception as e:
            print(f"[Capture] Lỗi khi process_packet: {e}")
        return None

    def _clean_old_flows(self, timeout=60):
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
    