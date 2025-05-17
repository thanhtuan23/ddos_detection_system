# src/ddos_detection_system/core/prevention_engine.py
import subprocess
import threading
import time
import logging
from typing import Dict, List, Any, Tuple, Set

class PreventionEngine:
    """
    Module ngăn chặn DDoS sử dụng iptables để chặn các nguồn tấn công.
    """
    
    def __init__(self, block_duration: int = 300, whitelist: List[str] = None):
        """
        Khởi tạo engine ngăn chặn DDoS.
        
        Args:
            block_duration: Thời gian chặn địa chỉ IP (giây)
            whitelist: Danh sách các địa chỉ IP không nên chặn
        """
        self.block_duration = block_duration
        self.whitelist = set(whitelist or [])
        self.blocked_ips = {}  # Lưu trữ các IP bị chặn và thời gian hết hạn
        self.lock = threading.Lock()
        self.logger = logging.getLogger("ddos_prevention")
        # src/ddos_detection_system/core/prevention_engine.py (continued)
        self.cleanup_thread = None
        self.running = False
        
        # Khởi tạo chain iptables riêng để dễ dàng quản lý
        self._initialize_iptables()
    
    def _initialize_iptables(self):
        """Khởi tạo chain iptables cho hệ thống phòng chống DDoS."""
        try:
            # Kiểm tra xem chain đã tồn tại chưa
            check_cmd = ["iptables", "-L", "DDOS_PROTECTION"]
            result = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if result.returncode != 0:
                # Tạo chain mới nếu chưa tồn tại
                subprocess.run(["iptables", "-N", "DDOS_PROTECTION"], check=True)
                
                # Thêm chain mới vào INPUT chain
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
            
        # Xóa tất cả các IP bị chặn
        with self.lock:
            for ip in list(self.blocked_ips.keys()):
                self._unblock_ip(ip)
                
        # Xóa chain DDOS_PROTECTION khỏi INPUT chain
        try:
            subprocess.run(["iptables", "-D", "INPUT", "-j", "DDOS_PROTECTION"], 
                          check=False, stderr=subprocess.PIPE)
            
            # Flush và xóa chain DDOS_PROTECTION
            subprocess.run(["iptables", "-F", "DDOS_PROTECTION"], 
                          check=False, stderr=subprocess.PIPE)
            subprocess.run(["iptables", "-X", "DDOS_PROTECTION"], 
                          check=False, stderr=subprocess.PIPE)
        except Exception as e:
            self.logger.error(f"Lỗi khi dọn dẹp iptables: {e}")
            
        self.logger.info("Engine ngăn chặn DDoS đã dừng")
    
    def block_ip(self, ip: str, attack_info: Dict[str, Any]) -> bool:
        """
        Chặn một địa chỉ IP dựa trên thông tin tấn công.
        
        Args:
            ip: Địa chỉ IP cần chặn
            attack_info: Thông tin chi tiết về cuộc tấn công
            
        Returns:
            True nếu việc chặn thành công, False nếu không
        """
        if not ip or ip in self.whitelist:
            return False
            
        with self.lock:
            # Nếu IP đã bị chặn, chỉ cập nhật thời gian hết hạn
            if ip in self.blocked_ips:
                self.blocked_ips[ip] = time.time() + self.block_duration
                self.logger.info(f"Đã gia hạn thời gian chặn cho IP {ip}")
                return True
                
            try:
                attack_type = attack_info.get('attack_type', 'Unknown')
                confidence = attack_info.get('confidence', 0)
                
                # Thêm quy tắc iptables để chặn IP
                cmd = ["iptables", "-A", "DDOS_PROTECTION", "-s", ip, "-j", "DROP"]
                subprocess.run(cmd, check=True)
                
                # Lưu thông tin IP bị chặn và thời gian hết hạn
                self.blocked_ips[ip] = time.time() + self.block_duration
                
                self.logger.warning(
                    f"Chặn IP {ip} do tấn công {attack_type} "
                    f"(độ tin cậy: {confidence:.2f}) trong {self.block_duration} giây"
                )
                return True
                
            except Exception as e:
                self.logger.error(f"Lỗi khi chặn IP {ip}: {e}")
                return False
    
    def unblock_ip(self, ip: str) -> bool:
        """
        Bỏ chặn một địa chỉ IP.
        
        Args:
            ip: Địa chỉ IP cần bỏ chặn
            
        Returns:
            True nếu việc bỏ chặn thành công, False nếu không
        """
        with self.lock:
            if ip not in self.blocked_ips:
                return False
                
            success = self._unblock_ip(ip)
            if success:
                del self.blocked_ips[ip]
            return success
    
    def _unblock_ip(self, ip: str) -> bool:
        """
        Thực hiện bỏ chặn một địa chỉ IP.
        
        Args:
            ip: Địa chỉ IP cần bỏ chặn
            
        Returns:
            True nếu thành công, False nếu không
        """
        try:
            cmd = ["iptables", "-D", "DDOS_PROTECTION", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True)
            self.logger.info(f"Đã bỏ chặn IP {ip}")
            return True
        except Exception as e:
            self.logger.error(f"Lỗi khi bỏ chặn IP {ip}: {e}")
            return False
    
    def _cleanup_expired_blocks(self):
        """Xóa các quy tắc chặn đã hết hạn."""
        while self.running:
            time.sleep(10)  # Kiểm tra mỗi 10 giây
            
            current_time = time.time()
            expired_ips = []
            
            with self.lock:
                # Tìm các IP đã hết thời gian chặn
                for ip, expiry_time in self.blocked_ips.items():
                    if current_time >= expiry_time:
                        expired_ips.append(ip)
                
                # Bỏ chặn các IP đã hết hạn
                for ip in expired_ips:
                    success = self._unblock_ip(ip)
                    if success:
                        del self.blocked_ips[ip]
    
    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """
        Lấy danh sách các IP đang bị chặn.
        
        Returns:
            Danh sách các dict chứa thông tin về IP bị chặn
        """
        current_time = time.time()
        blocked_list = []
        
        with self.lock:
            for ip, expiry_time in self.blocked_ips.items():
                remaining_time = max(0, expiry_time - current_time)
                blocked_list.append({
                    'ip': ip,
                    'remaining_time': int(remaining_time),
                    'expiry_time': time.strftime('%Y-%m-%d %H:%M:%S', 
                                              time.localtime(expiry_time))
                })
                
        return blocked_list
    
    def mitigate_attack(self, attack_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Thực hiện các biện pháp giảm thiểu tác động của cuộc tấn công DDoS.
        
        Args:
            attack_info: Thông tin về cuộc tấn công
            
        Returns:
            Dict chứa kết quả của các hành động giảm thiểu
        """
        flow_key = attack_info.get('flow_key', '')
        attack_type = attack_info.get('attack_type', 'Unknown')
        
        # Trích xuất IP nguồn từ flow_key
        src_ip = None
        if flow_key and '-' in flow_key:
            try:
                src_part = flow_key.split('-')[0]
                src_ip = src_part.split(':')[0]
            except:
                self.logger.error(f"Không thể phân tích flow_key: {flow_key}")
        
        result = {'success': False, 'actions': []}
        
        if not src_ip:
            return result
            
        # Triển khai các biện pháp giảm thiểu dựa trên loại tấn công
        if attack_type == 'Syn':
            # Đối với SYN Flood, chặn IP và giảm thời gian SYN-RECEIVED timeout
            try:
                # Chặn IP nguồn
                if self.block_ip(src_ip, attack_info):
                    result['actions'].append(f"Đã chặn IP {src_ip}")
                    
                # Điều chỉnh tham số kernel cho SYN flood protection
                subprocess.run(["sysctl", "-w", "net.ipv4.tcp_syncookies=1"], check=True)
                subprocess.run(["sysctl", "-w", "net.ipv4.tcp_max_syn_backlog=2048"], check=True)
                subprocess.run(["sysctl", "-w", "net.ipv4.tcp_synack_retries=2"], check=True)
                result['actions'].append("Kích hoạt SYN cookies và điều chỉnh tham số kernel")
                
                result['success'] = True
            except Exception as e:
                self.logger.error(f"Lỗi khi giảm thiểu SYN Flood: {e}")
                
        elif attack_type in ['UDP', 'UDPLag']:
            # Đối với UDP Flood, chặn IP và giới hạn tốc độ UDP
            try:
                # Chặn IP nguồn
                if self.block_ip(src_ip, attack_info):
                    result['actions'].append(f"Đã chặn IP {src_ip}")
                
                # Thêm quy tắc iptables để giới hạn tốc độ UDP
                limit_cmd = [
                    "iptables", "-A", "DDOS_PROTECTION", "-p", "udp", 
                    "-m", "limit", "--limit", "100/s", "-j", "ACCEPT"
                ]
                subprocess.run(limit_cmd, check=True)
                
                # Thêm quy tắc cuối cùng để DROP tất cả các gói UDP vượt quá giới hạn
                drop_cmd = ["iptables", "-A", "DDOS_PROTECTION", "-p", "udp", "-j", "DROP"]
                subprocess.run(drop_cmd, check=True)
                
                result['actions'].append("Đã giới hạn tốc độ gói UDP")
                result['success'] = True
            except Exception as e:
                self.logger.error(f"Lỗi khi giảm thiểu UDP Flood: {e}")
                
        else:
            # Đối với các loại tấn công khác, áp dụng biện pháp chung
            try:
                if self.block_ip(src_ip, attack_info):
                    result['actions'].append(f"Đã chặn IP {src_ip}")
                    result['success'] = True
            except Exception as e:
                self.logger.error(f"Lỗi khi giảm thiểu tấn công {attack_type}: {e}")
                
        return result
    