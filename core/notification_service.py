# core/notification_service.py
import time
import threading
import logging
import json
from typing import Dict, Any, List, Callable, Optional
from utils.email_sender import EmailSender

class NotificationService:
    """
    Service for sending notifications about detected attacks.
    """
    
    def __init__(self, email_config: Dict[str, Any], cooldown_period: int = 300,
                 message_format: str = "html", critical_attack_types: List[str] = None,
                 min_confidence: float = 0.85):
        """
        Initialize the notification service.
        
        Args:
            email_config: Email configuration
            cooldown_period: Minimum time between notifications (seconds)
            message_format: Message format ("html" or "text")
            critical_attack_types: List of attack types considered critical
            min_confidence: Minimum confidence for notifications
        """
        self.logger = logging.getLogger("ddos_detection_system.core.notification_service")
        
        self.email_sender = EmailSender(**email_config)
        self.cooldown_period = cooldown_period
        self.message_format = message_format.lower()
        self.critical_attack_types = set(critical_attack_types) if critical_attack_types else set()
        self.min_confidence = min_confidence
        
        # State
        self.running = False
        self.last_notification_time = 0
        self.pending_notifications = []
        self.lock = threading.RLock()
        
        # Notification thread
        self.notification_thread = None
        
        # Callbacks
        self.callbacks = {
            'attack_detected': []
        }
        
        self.logger.info(f"Notification service initialized with cooldown={cooldown_period}s, format={message_format}")
    
    def start(self):
        """Start the notification service."""
        with self.lock:
            if self.running:
                self.logger.warning("Notification service already running")
                return
            
            self.running = True
            
            # Start notification thread
            self.notification_thread = threading.Thread(target=self._notification_loop)
            self.notification_thread.daemon = True
            self.notification_thread.start()
            
            self.logger.info("Notification service started")
    
    def stop(self):
        """Stop the notification service."""
        with self.lock:
            if not self.running:
                self.logger.warning("Notification service not running")
                return
            
            self.running = False
            
            # Wait for thread to terminate
            if self.notification_thread:
                self.notification_thread.join(timeout=2.0)
            
            self.logger.info("Notification service stopped")
    
    def register_callback(self, event: str, callback: Callable[[Dict[str, Any]], None]):
        """
        Register a callback function for an event.
        
        Args:
            event: Event name
            callback: Callback function
        """
        with self.lock:
            if event not in self.callbacks:
                self.callbacks[event] = []
            
            self.callbacks[event].append(callback)
            self.logger.debug(f"Registered callback for event: {event}")
    
    def notify(self, attack_info: Dict[str, Any]):
        """
        Send notification about an attack.
        
        Args:
            attack_info: Attack information
        """
        # Check confidence threshold
        confidence = attack_info.get('confidence', 0.0)
        if confidence < self.min_confidence:
            self.logger.debug(f"Skipping notification - confidence too low: {confidence} < {self.min_confidence}")
            return
        
        # Check if critical attack type (if list is specified)
        if self.critical_attack_types:
            attack_type = attack_info.get('attack_type', 'Unknown')
            if attack_type not in self.critical_attack_types:
                self.logger.debug(f"Skipping notification - non-critical attack type: {attack_type}")
                return
        
        # Trigger attack detected callbacks
        self._trigger_callbacks('attack_detected', attack_info)
        
        with self.lock:
            # Add to pending notifications
            self.pending_notifications.append(attack_info)
            self.logger.debug(f"Added attack to pending notifications: {attack_info.get('attack_type', 'Unknown')}")
    
    def _trigger_callbacks(self, event: str, data: Dict[str, Any]):
        """
        Trigger callbacks for an event.
        
        Args:
            event: Event name
            data: Event data
        """
        with self.lock:
            if event not in self.callbacks:
                return
            
            callbacks = self.callbacks[event].copy()
        
        # Call callbacks outside the lock
        for callback in callbacks:
            try:
                callback(data)
            except Exception as e:
                self.logger.error(f"Error in callback for event {event}: {e}", exc_info=True)
    
    def _notification_loop(self):
        """Thread function to process pending notifications."""
        self.logger.info("Starting notification loop")
        
        while self.running:
            try:
                # Check if it's time to send notifications
                current_time = time.time()
                
                with self.lock:
                    # Check if there are pending notifications and cooldown period has passed
                    if (self.pending_notifications and 
                        current_time - self.last_notification_time >= self.cooldown_period):
                        
                        # Send notification
                        self._send_notification(self.pending_notifications)
                        
                        # Update state
                        self.last_notification_time = current_time
                        self.pending_notifications = []
                
                # Sleep for a while
                time.sleep(5)
                
            except Exception as e:
                self.logger.error(f"Error in notification loop: {e}", exc_info=True)
                
        self.logger.info("Stopping notification loop")
    
    def _send_notification(self, attacks: List[Dict[str, Any]]):
        """
        Send notification about attacks.
        
        Args:
            attacks: List of attack information
        """
        try:
            # Prepare subject
            if len(attacks) == 1:
                attack = attacks[0]
                subject = f"DDoS Alert: {attack.get('attack_type', 'Unknown')} attack detected"
            else:
                subject = f"DDoS Alert: {len(attacks)} attacks detected"
            
            # Prepare message body
            if self.message_format == "html":
                body = self._create_html_message(attacks)
            else:
                body = self._create_text_message(attacks)
            
            # Send email
            self.email_sender.send_email(subject, body, is_html=(self.message_format == "html"))
            
            self.logger.info(f"Sent notification about {len(attacks)} attacks")
            
        except Exception as e:
            self.logger.error(f"Error sending notification: {e}", exc_info=True)
    
    def _create_html_message(self, attacks: List[Dict[str, Any]]) -> str:
        """
        Create HTML message for attacks.
        
        Args:
            attacks: List of attack information
            
        Returns:
            HTML message
        """
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                .high { background-color: #ffdddd; }
                .medium { background-color: #ffffcc; }
                .low { background-color: #e6f3ff; }
            </style>
        </head>
        <body>
            <h2>DDoS Attack Alert</h2>
            <p>The following DDoS attacks have been detected:</p>
            <table>
                <tr>
                    <th>Time</th>
                    <th>Attack Type</th>
                    <th>Source IP</th>
                    <th>Destination IP</th>
                    <th>Confidence</th>
                    <th>Status</th>
                </tr>
        """
        
        for attack in attacks:
            # Format timestamp
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", 
                                      time.localtime(attack.get('timestamp', time.time())))
            
            # Determine confidence class
            confidence = attack.get('confidence', 0.0)
            confidence_class = "high" if confidence >= 0.9 else "medium" if confidence >= 0.7 else "low"
            
            # Determine status
            status = "Blocked" if attack.get('blocked', False) else "Detected"
            
            html += f"""
                <tr class="{confidence_class}">
                    <td>{timestamp}</td>
                    <td>{attack.get('attack_type', 'Unknown')}</td>
                    <td>{attack.get('src_ip', 'Unknown')}</td>
                    <td>{attack.get('dst_ip', 'Unknown')}</td>
                    <td>{confidence:.2f}</td>
                    <td>{status}</td>
                </tr>
            """
        
        html += """
            </table>
            
            <h3>Attack Details</h3>
        """
        
        # Add details for each attack
        for i, attack in enumerate(attacks):
            details = attack.get('details', {})
            html += f"""
            <div>
                <h4>Attack #{i+1}: {attack.get('attack_type', 'Unknown')}</h4>
                <p><strong>Source:</strong> {attack.get('src_ip', 'Unknown')}:{attack.get('src_port', 'Unknown')}</p>
                <p><strong>Destination:</strong> {attack.get('dst_ip', 'Unknown')}:{attack.get('dst_port', 'Unknown')}</p>
                <p><strong>Protocol:</strong> {attack.get('protocol', 'Unknown')}</p>
                <p><strong>Packet Rate:</strong> {attack.get('packet_rate', 0):.2f} packets/sec</p>
                <p><strong>Confidence:</strong> {attack.get('confidence', 0.0):.2f}</p>
                <p><strong>Description:</strong> {details.get('attack_description', 'No description available')}</p>
            </div>
            <hr>
            """
        
        html += """
        </body>
        </html>
        """
        
        return html
    
    def _create_text_message(self, attacks: List[Dict[str, Any]]) -> str:
        """
        Create text message for attacks.
        
        Args:
            attacks: List of attack information
            
        Returns:
            Text message
        """
        text = "DDoS Attack Alert\n"
        text += "=================\n\n"
        text += f"The following {len(attacks)} DDoS attacks have been detected:\n\n"
        
        for i, attack in enumerate(attacks):
            # Format timestamp
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S", 
                                      time.localtime(attack.get('timestamp', time.time())))
            
            text += f"Attack #{i+1}:\n"
            text += f"Time: {timestamp}\n"
            text += f"Type: {attack.get('attack_type', 'Unknown')}\n"
            text += f"Source: {attack.get('src_ip', 'Unknown')}:{attack.get('src_port', 'Unknown')}\n"
            text += f"Destination: {attack.get('dst_ip', 'Unknown')}:{attack.get('dst_port', 'Unknown')}\n"
            text += f"Protocol: {attack.get('protocol', 'Unknown')}\n"
            text += f"Confidence: {attack.get('confidence', 0.0):.2f}\n"
            text += f"Status: {'Blocked' if attack.get('blocked', False) else 'Detected'}\n"
            
            # Add attack description if available
            details = attack.get('details', {})
            description = details.get('attack_description', 'No description available')
            text += f"Description: {description}\n\n"
        
        text += "\nThis is an automated message from your DDoS Detection System."
        
        return text