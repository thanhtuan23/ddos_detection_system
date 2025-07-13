# core/prevention_engine.py
import time
import threading
import logging
import subprocess
import ipaddress
from typing import Dict, Any, List, Set, Optional

class PreventionEngine:
    """
    Engine for preventing DDoS attacks by blocking malicious IPs.
    """
    
    def __init__(self, block_duration: int = 300, whitelist: List[str] = None,
                 auto_block: bool = False, min_alerts_for_autoblock: int = 3,
                 alert_window: int = 60, auto_block_attack_types: List[str] = None):
        """
        Initialize the prevention engine.
        
        Args:
            block_duration: Default duration to block IPs (seconds)
            whitelist: List of IPs that should never be blocked
            auto_block: Whether to automatically block detected attacks
            min_alerts_for_autoblock: Minimum alerts before auto-blocking
            alert_window: Time window for counting alerts (seconds)
            auto_block_attack_types: List of attack types to auto-block (if empty, all are blocked)
        """
        self.logger = logging.getLogger("ddos_detection_system.core.prevention_engine")
        
        self.block_duration = block_duration
        self.whitelist = set(whitelist) if whitelist else set(['127.0.0.1', '::1'])
        self.auto_block = auto_block
        self.min_alerts_for_autoblock = min_alerts_for_autoblock
        self.alert_window = alert_window
        self.auto_block_attack_types = set(auto_block_attack_types) if auto_block_attack_types else set()
        
        # Track blocked IPs: IP -> expiry time
        self.blocked_ips = {}
        
        # Track blocked IPs by attack type: attack_type -> set of IPs
        self.blocked_by_attack_type = {}
        
        # Track recent alerts: IP -> list of alert timestamps
        self.recent_alerts = {}
        
        # Running state
        self.running = False
        self.unblock_thread = None
        self.lock = threading.RLock()
        
        # Initialize iptables
        self._initialize_iptables()
        
        self.logger.info(f"Prevention engine initialized with block_duration={block_duration}, auto_block={auto_block}")
    
    def start(self):
        """Start the prevention engine."""
        with self.lock:
            if self.running:
                self.logger.warning("Prevention engine already running")
                return
            
            self.running = True
            
            # Start unblock thread
            self.unblock_thread = threading.Thread(target=self._auto_unblock_loop)
            self.unblock_thread.daemon = True
            self.unblock_thread.start()
            
            self.logger.info("DDoS prevention engine started")
    
    def stop(self):
        """Stop the prevention engine."""
        with self.lock:
            if not self.running:
                self.logger.warning("Prevention engine not running")
                return
            
            self.running = False
            
            # Wait for thread to terminate
            if self.unblock_thread:
                self.unblock_thread.join(timeout=2.0)
            
            self.logger.info("DDoS prevention engine stopped")
    
    def block_ip(self, ip: str, attack_type: str = "Unknown", confidence: float = 0.0, duration: int = None) -> bool:
        """
        Block an IP address.
        
        Args:
            ip: IP address to block
            attack_type: Type of attack
            confidence: Detection confidence
            duration: Block duration in seconds (if None, use default)
            
        Returns:
            True if blocked successfully, False otherwise
        """
        # Check if IP is valid and not whitelisted
        if not ip or self._is_ip_whitelisted(ip):
            self.logger.info(f"Skipping block for IP {ip} (whitelisted or empty)")
            return False
        
        return self._do_block_ip(ip, attack_type, confidence, duration)
    
    def manual_block(self, ip: str, duration: int = None) -> bool:
        """
        Manually block an IP address.
        
        Args:
            ip: IP address to block
            duration: Block duration in seconds (if None, use default)
            
        Returns:
            True if blocked successfully, False otherwise
        """
        if not ip or self._is_ip_whitelisted(ip):
            self.logger.info(f"Skipping manual block for IP {ip} (whitelisted or empty)")
            return False
            
        return self._do_block_ip(ip, "Manual", 1.0, duration)
    
    def unblock_ip(self, ip: str) -> bool:
        """
        Unblock an IP address.
        
        Args:
            ip: IP address to unblock
            
        Returns:
            True if unblocked successfully, False otherwise
        """
        with self.lock:
            if ip in self.blocked_ips:
                if self._unblock_ip(ip):
                    # Remove from blocked IPs
                    del self.blocked_ips[ip]
                    
                    # Remove from attack type blocks
                    for attack_ips in self.blocked_by_attack_type.values():
                        if ip in attack_ips:
                            attack_ips.remove(ip)
                            
                    self.logger.info(f"Unblocked IP {ip}")
                    
                    # Update IP status in database
                    try:
                        from utils.ddos_logger import update_ip_blocked_status
                        update_ip_blocked_status(ip, False)
                    except Exception as e:
                        self.logger.error(f"Error updating IP status: {e}")
                        
                    return True
                    
        return False
    
    def get_blocked_ips(self) -> List[Dict[str, Any]]:
        """
        Get list of currently blocked IPs.
        
        Returns:
            List of dicts with IP info
        """
        with self.lock:
            current_time = time.time()
            result = []
            
            for ip, expiry_time in self.blocked_ips.items():
                # Find attack type
                attack_type = "Unknown"
                for atype, ips in self.blocked_by_attack_type.items():
                    if ip in ips:
                        attack_type = atype
                        break
                
                # Add to result
                result.append({
                    'ip': ip,
                    'attack_type': attack_type,
                    'expiry_time': expiry_time,
                    'remaining_time': max(0, expiry_time - current_time)
                })
                
            return result
    
    def _do_block_ip(self, ip: str, attack_type: str, confidence: float, duration: int = None) -> bool:
        """
        Internal method to block an IP.
        
        Args:
            ip: IP address to block
            attack_type: Type of attack
            confidence: Detection confidence
            duration: Block duration in seconds
            
        Returns:
            True if blocked successfully, False otherwise
        """
        try:
            with self.lock:
                # Check if already blocked
                if ip in self.blocked_ips:
                    # Update expiry time if new duration would be longer
                    current_expiry = self.blocked_ips[ip]
                    block_duration = duration or self.block_duration
                    new_expiry = time.time() + block_duration
                    
                    if new_expiry > current_expiry:
                        self.blocked_ips[ip] = new_expiry
                        self.logger.info(f"Extended block for IP {ip} until {time.ctime(new_expiry)}")
                    
                    # Add to attack type if not already there
                    if attack_type not in self.blocked_by_attack_type:
                        self.blocked_by_attack_type[attack_type] = set()
                    self.blocked_by_attack_type[attack_type].add(ip)
                    
                    return True
                
                # Add to iptables
                if not self._block_ip(ip):
                    return False
                
                # Add to blocked IPs
                block_duration = duration or self.block_duration
                expiry_time = time.time() + block_duration
                self.blocked_ips[ip] = expiry_time
                
                # Add to attack type blocks
                if attack_type not in self.blocked_by_attack_type:
                    self.blocked_by_attack_type[attack_type] = set()
                self.blocked_by_attack_type[attack_type].add(ip)
                
                self.logger.info(f"Blocked IP {ip} for {attack_type} attack until {time.ctime(expiry_time)}")
                
                # Update IP status in database
                try:
                    from utils.ddos_logger import update_ip_blocked_status
                    update_ip_blocked_status(ip, True)
                except Exception as e:
                    self.logger.error(f"Error updating IP status: {e}")
                
                return True
                
        except Exception as e:
            self.logger.error(f"Error blocking IP {ip}: {e}", exc_info=True)
            return False
    
    def _block_ip(self, ip: str) -> bool:
        """
        Add iptables rule to block an IP.
        
        Args:
            ip: IP address to block
            
        Returns:
            True if successful, False otherwise
        """
        try:
            cmd = ["iptables", "-A", "DDOS_PROTECTION", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True)
            return True
        except Exception as e:
            self.logger.error(f"Error adding block rule for IP {ip}: {e}", exc_info=True)
            return False
    
    def _unblock_ip(self, ip: str) -> bool:
        """
        Remove iptables rule to unblock an IP.
        
        Args:
            ip: IP address to unblock
            
        Returns:
            True if successful, False otherwise
        """
        try:
            cmd = ["iptables", "-D", "DDOS_PROTECTION", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True)
            return True
        except Exception as e:
            self.logger.error(f"Error removing block rule for IP {ip}: {e}", exc_info=True)
            return False
    
    def _cleanup_expired_blocks(self):
        """Clean up expired IP blocks."""
        with self.lock:
            current_time = time.time()
            expired_ips = [ip for ip, expiry_time in self.blocked_ips.items() if expiry_time <= current_time]
            
            for ip in expired_ips:
                if self._unblock_ip(ip):
                    # Remove from blocked IPs
                    del self.blocked_ips[ip]
                    
                    # Remove from attack type blocks
                    for attack_ips in self.blocked_by_attack_type.values():
                        if ip in attack_ips:
                            attack_ips.remove(ip)
                            
                    self.logger.info(f"Auto-unblocked IP {ip} (expired)")
                    
                    # Update IP status in database
                    try:
                        from utils.ddos_logger import update_ip_blocked_status
                        update_ip_blocked_status(ip, False)
                    except Exception as e:
                        self.logger.error(f"Error updating IP status: {e}")
    
    def _auto_unblock_loop(self):
        """Thread function to automatically unblock expired IPs."""
        self.logger.info("Starting auto-unblock loop")
        
        while self.running:
            try:
                # Clean up expired blocks
                self._cleanup_expired_blocks()
                
                # Sleep for a while
                time.sleep(10)
                
            except Exception as e:
                self.logger.error(f"Error in auto-unblock loop: {e}", exc_info=True)
                
        self.logger.info("Stopping auto-unblock loop")
    
    def _initialize_iptables(self):
        """Initialize iptables chain for DDoS protection."""
        try:
            # Check if chain exists
            check_cmd = ["iptables", "-L", "DDOS_PROTECTION"]
            result = subprocess.run(check_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            if result.returncode != 0:
                # Create new chain
                subprocess.run(["iptables", "-N", "DDOS_PROTECTION"], check=True)
                # Add chain to INPUT
                subprocess.run(["iptables", "-I", "INPUT", "-j", "DDOS_PROTECTION"], check=True)
                
            self.logger.info("Initialized iptables chain DDOS_PROTECTION")
        except Exception as e:
            self.logger.error(f"Error initializing iptables: {e}", exc_info=True)
    
    def _is_ip_whitelisted(self, ip: str) -> bool:
        """
        Check if an IP is whitelisted.
        
        Args:
            ip: IP address to check
            
        Returns:
            True if whitelisted, False otherwise
        """
        # Direct match
        if ip in self.whitelist:
            return True
        
        # Check if valid IP
        try:
            ip_obj = ipaddress.ip_address(ip)
            
            # Check if in whitelisted networks
            for white_ip in self.whitelist:
                # Check if whitelist entry is a network
                if '/' in white_ip:
                    try:
                        network = ipaddress.ip_network(white_ip, strict=False)
                        if ip_obj in network:
                            return True
                    except ValueError:
                        pass
        except ValueError:
            self.logger.warning(f"Invalid IP address: {ip}")
            return False
        return False