# utils/ddos_logger.py
import os
import csv
import time
import logging
import ipaddress
from typing import Dict, Any, List, Optional

class DDoSLogger:
    """
    Logger for DDoS attack information.
    """
    
    def __init__(self, log_dir: str = 'logs'):
        """
        Initialize the DDoS logger.
        
        Args:
            log_dir: Directory for log files
        """
        # Ensure log directory exists
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        
        # Log files
        self.attack_log_file = os.path.join(log_dir, 'ddos_attacks.log')
        self.ip_log_file = os.path.join(log_dir, 'ddos_ips.log')
        
        # Initialize log files
        self._initialize_log_files()
        
        # Track logged IPs to avoid duplicates
        self.logged_ips = set()
        self._load_existing_ips()
        
        # Set up logger
        self.logger = logging.getLogger("ddos_detection_system.utils.ddos_logger")
        self.logger.info("DDoS logger initialized")
    
    def _initialize_log_files(self):
        """Initialize log files if they don't exist."""
        # Create attack log file if it doesn't exist
        if not os.path.exists(self.attack_log_file):
            with open(self.attack_log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
                    'protocol', 'attack_type', 'confidence', 'blocked'
                ])
                
        # Create IP log file if it doesn't exist
        if not os.path.exists(self.ip_log_file):
            with open(self.ip_log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'ip', 'first_seen', 'last_seen', 'attack_types', 'block_count', 'is_blocked'
                ])
    
    def _load_existing_ips(self):
        """Load existing IPs from the IP log file."""
        try:
            if os.path.exists(self.ip_log_file):
                with open(self.ip_log_file, 'r', newline='') as f:
                    reader = csv.reader(f)
                    next(reader)  # Skip header
                    for row in reader:
                        if row and len(row) > 0:
                            self.logged_ips.add(row[0])  # IP is first column
                            
        except Exception as e:
            self.logger.error(f"Error loading existing IPs: {e}", exc_info=True)
    
    def log_attack(self, attack_info: Dict[str, Any]):
        """
        Log attack information.
        
        Args:
            attack_info: Attack information dictionary
        """
        try:
            # Get attack details
            timestamp = attack_info.get('timestamp', time.strftime("%Y-%m-%d %H:%M:%S"))
            src_ip = attack_info.get('src_ip', 'unknown')
            dst_ip = attack_info.get('dst_ip', 'unknown')
            src_port = attack_info.get('src_port', 0)
            dst_port = attack_info.get('dst_port', 0)
            protocol = attack_info.get('protocol', 'unknown')
            attack_type = attack_info.get('attack_type', 'unknown')
            confidence = attack_info.get('confidence', 0.0)
            blocked = attack_info.get('blocked', False)
            
            # Format timestamp if it's a number
            if isinstance(timestamp, (int, float)):
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
            
            # Log to attack log file
            with open(self.attack_log_file, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    timestamp, src_ip, dst_ip, src_port, dst_port, 
                    protocol, attack_type, confidence, blocked
                ])
            
            # Log IP information
            if self._is_valid_ip(src_ip):
                self._log_ip(src_ip, timestamp, attack_type, confidence)
            
            self.logger.debug(f"Logged attack: {attack_type} from {src_ip} to {dst_ip}")
            
        except Exception as e:
            self.logger.error(f"Error logging attack: {e}", exc_info=True)
    
    def _log_ip(self, ip: str, timestamp: str, attack_type: str, confidence: float):
        """
        Log information about an attacking IP.
        
        Args:
            ip: IP address
            timestamp: Timestamp
            attack_type: Attack type
            confidence: Confidence
        """
        try:
            # Convert timestamp to standard format if needed
            if not isinstance(timestamp, str):
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S", 
                                         time.localtime(timestamp))
            
            # Check if IP is already logged
            is_new = ip not in self.logged_ips
            
            # Prepare IP data
            ip_data = {
                'ip': ip,
                'first_seen': timestamp if is_new else '',
                'last_seen': timestamp,
                'attack_types': attack_type,
                'block_count': '0',
                'is_blocked': 'False'
            }
            
            # Update IP log
            self._update_ip_log(ip_data)
            
            # Add to tracked IPs
            self.logged_ips.add(ip)
            
        except Exception as e:
            self.logger.error(f"Error logging IP {ip}: {e}", exc_info=True)
    
    def _update_ip_log(self, ip_data: Dict[str, str]):
        """
        Update IP log with new data.
        
        Args:
            ip_data: IP data dictionary
        """
        try:
            # Load all existing data
            all_ip_data = []
            if os.path.exists(self.ip_log_file):
                with open(self.ip_log_file, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if row['ip'] != ip_data['ip']:
                            all_ip_data.append(row)
                        else:
                            # Update existing IP data
                            if not ip_data['first_seen']:
                                ip_data['first_seen'] = row.get('first_seen', '')
                            
                            # Combine attack types
                            existing_types = row.get('attack_types', '').split(',')
                            new_types = ip_data['attack_types'].split(',')
                            all_types = set(existing_types + new_types)
                            if '' in all_types:
                                all_types.remove('')
                            ip_data['attack_types'] = ','.join(all_types)
                            
                            # Preserve block count and status
                            ip_data['block_count'] = row.get('block_count', '0')
                            ip_data['is_blocked'] = row.get('is_blocked', 'False')
                            
            # Add new IP data
            all_ip_data.append(ip_data)
            
            # Write back to file
            with open(self.ip_log_file, 'w', newline='') as f:
                                fieldnames = ['ip', 'first_seen', 'last_seen', 'attack_types', 'block_count', 'is_blocked']
                                writer = csv.DictWriter(f, fieldnames=fieldnames)
                                writer.writeheader()
                                writer.writerows(all_ip_data)
                
        except Exception as e:
            self.logger.error(f"Error updating IP log: {e}", exc_info=True)
    
    def update_ip_blocked_status(self, ip: str, blocked: bool):
        """
        Update the blocked status of an IP.
        
        Args:
            ip: IP address
            blocked: Whether the IP is blocked
        """
        try:
            # Update attack log with blocked status
            self._update_attack_log_blocked_status(ip, blocked)
            
            # Load all existing data
            all_ip_data = []
            found = False
            
            if os.path.exists(self.ip_log_file):
                with open(self.ip_log_file, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if row['ip'] == ip:
                            # Update block status
                            row['is_blocked'] = str(blocked)
                            
                            # Update block count if newly blocked
                            if blocked:
                                try:
                                    block_count = int(row.get('block_count', '0'))
                                    row['block_count'] = str(block_count + 1)
                                except ValueError:
                                    row['block_count'] = '1'
                            
                            found = True
                        
                        all_ip_data.append(row)
            
            # If IP not found, add it
            if not found and blocked:
                timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
                all_ip_data.append({
                    'ip': ip,
                    'first_seen': timestamp,
                    'last_seen': timestamp,
                    'attack_types': 'Manual',
                    'block_count': '1',
                    'is_blocked': 'True'
                })
                self.logged_ips.add(ip)
            
            # Write back to file
            with open(self.ip_log_file, 'w', newline='') as f:
                fieldnames = ['ip', 'first_seen', 'last_seen', 'attack_types', 'block_count', 'is_blocked']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(all_ip_data)
                
            self.logger.debug(f"Updated block status for IP {ip}: {blocked}")
                
        except Exception as e:
            self.logger.error(f"Error updating IP blocked status: {e}", exc_info=True)
    
    def _update_attack_log_blocked_status(self, ip: str, blocked: bool):
        """
        Update blocked status in attack log.
        
        Args:
            ip: IP address
            blocked: Whether the IP is blocked
        """
        try:
            # Load all existing data
            all_attack_data = []
            
            if os.path.exists(self.attack_log_file):
                with open(self.attack_log_file, 'r', newline='') as f:
                    reader = csv.reader(f)
                    header = next(reader)
                    all_attack_data.append(header)
                    
                    for row in reader:
                        if len(row) > 1 and row[1] == ip:  # src_ip is at index 1
                            row[8] = str(blocked)  # blocked is at index 8
                        all_attack_data.append(row)
                        
            # Write back to file
            with open(self.attack_log_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerows(all_attack_data)
                
        except Exception as e:
            self.logger.error(f"Error updating attack log blocked status: {e}", exc_info=True)
    
    def get_all_attack_ips(self) -> List[Dict[str, Any]]:
        """
        Get all attacking IPs.
        
        Returns:
            List of dictionaries with IP information
        """
        try:
            ip_list = []
            
            if os.path.exists(self.ip_log_file):
                with open(self.ip_log_file, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        ip_list.append({
                            'ip': row['ip'],
                            'first_seen': row['first_seen'],
                            'last_seen': row['last_seen'],
                            'attack_types': row['attack_types'].split(','),
                            'block_count': int(row.get('block_count', '0')),
                            'is_blocked': row.get('is_blocked', 'False') == 'True'
                        })
                        
            return ip_list
            
        except Exception as e:
            self.logger.error(f"Error getting attack IPs: {e}", exc_info=True)
            return []
    
    def get_recent_attacks(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Get recent attacks.
        
        Args:
            limit: Maximum number of attacks to return
            
        Returns:
            List of dictionaries with attack information
        """
        try:
            attacks = []
            
            if os.path.exists(self.attack_log_file):
                with open(self.attack_log_file, 'r', newline='') as f:
                    reader = csv.reader(f)
                    header = next(reader)
                    
                    # Get all rows
                    rows = list(reader)
                    
                    # Sort by timestamp (most recent first)
                    rows.sort(key=lambda row: row[0] if row else "", reverse=True)
                    
                    # Take only the specified limit
                    for row in rows[:limit]:
                        if len(row) >= 9:
                            attacks.append({
                                'timestamp': row[0],
                                'src_ip': row[1],
                                'dst_ip': row[2],
                                'src_port': int(row[3]) if row[3].isdigit() else 0,
                                'dst_port': int(row[4]) if row[4].isdigit() else 0,
                                'protocol': row[5],
                                'attack_type': row[6],
                                'confidence': float(row[7]) if row[7] else 0.0,
                                'blocked': row[8] == 'True'
                            })
                        
            return attacks
            
        except Exception as e:
            self.logger.error(f"Error getting recent attacks: {e}", exc_info=True)
            return []
    
    def _is_valid_ip(self, ip: str) -> bool:
        """
        Check if a string is a valid IP address.
        
        Args:
            ip: String to check
            
        Returns:
            True if valid IP, False otherwise
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False


# Global instance for convenient access
ddos_logger = DDoSLogger()

# Utility functions that use the global instance

def log_attack(attack_info: Dict[str, Any]):
    """
    Log an attack.
    
    Args:
        attack_info: Attack information dictionary
    """
    ddos_logger.log_attack(attack_info)

def update_ip_blocked_status(ip: str, blocked: bool):
    """
    Update IP blocked status.
    
    Args:
        ip: IP address
        blocked: Whether the IP is blocked
    """
    ddos_logger.update_ip_blocked_status(ip, blocked)

def get_all_attack_ips() -> List[Dict[str, Any]]:
    """
    Get all attacking IPs.
    
    Returns:
        List of dictionaries with IP information
    """
    return ddos_logger.get_all_attack_ips()

def get_recent_attacks(limit: int = 100) -> List[Dict[str, Any]]:
    """
    Get recent attacks.
    
    Args:
        limit: Maximum number of attacks to return
        
    Returns:
        List of dictionaries with attack information
    """
    return ddos_logger.get_recent_attacks(limit)