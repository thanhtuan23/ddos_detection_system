import subprocess
import threading
import time
import logging
from collections import defaultdict
from typing import Dict, List, Any

# Bỏ qua nếu bạn không dùng logging ngoài
try:
    from utils.ddos_logger import update_ip_blocked_status
except ImportError:
    def update_ip_blocked_status(ip, status):
        pass

class PreventionEngine:
    """
    Module ngăn chặn DDoS sử dụng iptables để chặn các nguồn tấn công.
    """
    def __init__(self, block_duration: int = 300, whitelist: List[str] = None):
        """
        Khởi tạo engine ngăn chặn DDoS.
        """
        self.block_duration = block_duration
        self.whitelist = set(whitelist or ['127.0.0.1', '192.168.140.1'])
        self.blocked_ips = {}  # ip: expiry_time
        self.lock = threading.Lock()
        self.logger = logging.getLogger("ddos_prevention")
        self.running = False
        self.cleanup_thread = None

        self.blocked_by_attack_type = defaultdict(set)
        self.unblock_thread = threading.Thread(target=self._auto_unblock_loop)
        self.unblock_thread.daemon = True
        self.unblock_thread.start()
        
        # Khởi tạo chain iptables riêng để dễ dàng quản lý
        self._initialize_iptables()
    
    def _initialize_iptables(self):
        """Khởi tạo chain iptables cho hệ thống phòng chống DDoS."""
        try:
            check_cmd = ["iptables", "-L", "DDOS_PROTECTION"]
            result = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode != 0:
                subprocess.run(["iptables", "-N", "DDOS_PROTECTION"], check=True)
                subprocess.run(["iptables", "-I", "INPUT", "-j", "DDOS_PROTECTION"], check=True)
            self.logger.info("Đã khởi tạo iptables chain DDOS_PROTECTION")
        except Exception as e:
            self.logger.error(f"Lỗi khi khởi tạo iptables: {e}")
    
    def start(self):
        """Bắt đầu engine ngăn chặn DDoS."""
        self.running = True
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired_blocks)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()
        self.logger.info("Engine ngăn chặn DDoS đã bắt đầu")
        
    def stop(self):
        """Dừng engine ngăn chặn DDoS và xóa tất cả các quy tắc đã thiết lập."""
        self.running = False
        if self.cleanup_thread:
            self.cleanup_thread.join(timeout=2.0)
        with self.lock:
            for ip in list(self.blocked_ips.keys()):
                self._unblock_ip(ip)
        try:
            subprocess.run(["iptables", "-D", "INPUT", "-j", "DDOS_PROTECTION"], check=False)
            subprocess.run(["iptables", "-F", "DDOS_PROTECTION"], check=False)
            subprocess.run(["iptables", "-X", "DDOS_PROTECTION"], check=False)
        except Exception as e:
            self.logger.error(f"Lỗi khi dọn dẹp iptables: {e}")
        self.logger.info("Engine ngăn chặn DDoS đã dừng")
    
    def block_ip(self, ip: str, attack_info: Dict[str, Any]) -> bool:
        """Chặn một địa chỉ IP dựa trên thông tin tấn công."""
        if not ip or ip in self.whitelist:
            self.logger.info(f"Bỏ qua không chặn IP {ip} (whitelist hoặc rỗng)")
            return False
        with self.lock:
            if ip in self.blocked_ips:
                self.blocked_ips[ip] = time.time() + self.block_duration
                self.logger.info(f"Gia hạn thời gian chặn cho IP {ip}")
                return True
            try:
                attack_type = attack_info.get('attack_type', 'Unknown')
                confidence = attack_info.get('confidence', 0)
                cmd = ["iptables", "-A", "DDOS_PROTECTION", "-s", ip, "-j", "DROP"]
                subprocess.run(cmd, check=True)
                self.blocked_ips[ip] = time.time() + self.block_duration
                self.blocked_by_attack_type[attack_type].add(ip)
                self.logger.warning(
                    f"Chặn IP {ip} do tấn công {attack_type} (độ tin cậy: {confidence:.2f}) trong {self.block_duration} giây"
                )
                update_ip_blocked_status(ip, True)
                return True
            except Exception as e:
                self.logger.error(f"Lỗi khi chặn IP {ip}: {e}")
                return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Bỏ chặn một địa chỉ IP."""
        with self.lock:
            if ip not in self.blocked_ips:
                return False
            success = self._unblock_ip(ip)
            if success:
                del self.blocked_ips[ip]
            return success
    
    def _unblock_ip(self, ip: str) -> bool:
        """Thực hiện bỏ chặn một địa chỉ IP."""
        try:
            cmd = ["iptables", "-D", "DDOS_PROTECTION", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True)
            update_ip_blocked_status(ip, False)
            self.logger.info(f"Đã bỏ chặn IP {ip}")
            return True
        except Exception as e:
            self.logger.error(f"Lỗi khi bỏ chặn IP {ip}: {e}")
            return False
    
    def _cleanup_expired_blocks(self):
        """Xóa các quy tắc chặn đã hết hạn."""
        while self.running:
            time.sleep(10)
            current_time = time.time()
            expired_ips = []
            with self.lock:
                for ip, expiry_time in list(self.blocked_ips.items()):
                    if current_time >= expiry_time:
                        expired_ips.append(ip)
                for ip in expired_ips:
                    success = self._unblock_ip(ip)
                    if success:
                        del self.blocked_ips[ip]
    
    def _auto_unblock_loop(self):
        """Luôn chạy ngầm để tự động bỏ chặn IP sau timeout."""
        while True:
            time.sleep(10)
            self._cleanup_expired_blocks()
    
    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """Lấy danh sách các IP đang bị chặn."""
        current_time = time.time()
        blocked_list = []
        with self.lock:
            for ip, expiry_time in self.blocked_ips.items():
                remaining_time = max(0, expiry_time - current_time)
                blocked_list.append({
                    'ip': ip,
                    'remaining_time': int(remaining_time),
                    'expiry_time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(expiry_time))
                })
        return blocked_list
    
    def mitigate_attack(self, attack_info: Dict[str, Any]) -> Dict[str, Any]:
        """Thực hiện các biện pháp giảm thiểu tác động của cuộc tấn công DDoS."""
        flow_key = attack_info.get('flow_key', '')
        attack_type = attack_info.get('attack_type', 'Unknown')
        src_ip = None
        if flow_key and '-' in flow_key:
            try:
                src_part = flow_key.split('-')[0]
                src_ip = src_part.split(':')[0]
            except Exception:
                self.logger.error(f"Không thể phân tích flow_key: {flow_key}")
        result = {'success': False, 'actions': []}
        if not src_ip:
            return result

        if attack_type == 'Syn':
            try:
                if self.block_ip(src_ip, attack_info):
                    result['actions'].append(f"Đã chặn IP {src_ip}")
                subprocess.run(["sysctl", "-w", "net.ipv4.tcp_syncookies=1"], check=True)
                subprocess.run(["sysctl", "-w", "net.ipv4.tcp_max_syn_backlog=2048"], check=True)
                subprocess.run(["sysctl", "-w", "net.ipv4.tcp_synack_retries=2"], check=True)
                result['actions'].append("Kích hoạt SYN cookies và điều chỉnh kernel")
                result['success'] = True
            except Exception as e:
                self.logger.error(f"Lỗi khi giảm thiểu SYN Flood: {e}")
        elif attack_type in ['UDP', 'UDPLag']:
            try:
                if self.block_ip(src_ip, attack_info):
                    result['actions'].append(f"Đã chặn IP {src_ip}")
                limit_cmd = [
                    "iptables", "-A", "DDOS_PROTECTION", "-p", "udp", 
                    "-m", "limit", "--limit", "100/s", "-j", "ACCEPT"
                ]
                subprocess.run(limit_cmd, check=True)
                drop_cmd = ["iptables", "-A", "DDOS_PROTECTION", "-p", "udp", "-j", "DROP"]
                subprocess.run(drop_cmd, check=True)
                result['actions'].append("Đã giới hạn tốc độ gói UDP")
                result['success'] = True
            except Exception as e:
                self.logger.error(f"Lỗi khi giảm thiểu UDP Flood: {e}")
        else:
            try:
                if self.block_ip(src_ip, attack_info):
                    result['actions'].append(f"Đã chặn IP {src_ip}")
                    result['success'] = True
            except Exception as e:
                self.logger.error(f"Lỗi khi giảm thiểu tấn công {attack_type}: {e}")
        return result
    # def get_blocked_by_attack_type(self) -> Dict[str, List[str]]:
    #     """Lấy danh sách các IP bị chặn theo loại tấn công."""
    #     with self.lock:
    #         return {attack_type: list(ips) for attack_type, ips in self.blocked_by_attack_type.items()}
    # def clear_blocked_by_attack_type(self, attack_type: str):
    #     """Xóa danh sách các IP bị chặn theo loại tấn công."""
    #     with self.lock:
    #         if attack_type in self.blocked_by_attack_type:
    #             for ip in list(self.blocked_by_attack_type[attack_type]):
    #                 self._unblock_ip(ip)
    #             del self.blocked_by_attack_type[attack_type]
    #             self.logger.info(f"Đã xóa danh sách chặn cho loại tấn công {attack_type}")
    #         else:
    #             self.logger.warning(f"Không tìm thấy loại tấn công {attack_type} trong danh sách chặn")
    # def clear_all_blocked_ips(self):
    #     """Xóa tất cả các IP bị chặn."""
    #     with self.lock:
    #         for ip in list(self.blocked_ips.keys()):
    #             self._unblock_ip(ip)
    #         self.blocked_ips.clear()
    #         self.blocked_by_attack_type.clear()
    #         self.logger.info("Đã xóa tất cả các IP bị chặn")