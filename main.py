# main.py
import os
import sys
import time
import queue
import threading
import logging
import logging.config
import configparser
from typing import Dict, Any, List, Optional
import warnings
from sklearn.exceptions import InconsistentVersionWarning

# Filter warnings to make logs cleaner
warnings.filterwarnings('ignore', message='.*Trying to unpickle estimator .* from version.*')
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)
warnings.filterwarnings('ignore', message='X does not have valid feature names')

# Configure logging early
logging.config.fileConfig('config/logging.conf')

# Reduce werkzeug log verbosity
werkzeug_logger = logging.getLogger('werkzeug')
werkzeug_logger.setLevel(logging.WARNING)

# Add root directory to path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import required modules
import psutil
from core.packet_capture import PacketCapture
from core.feature_extraction import FeatureExtractor
from core.detection_engine import DetectionEngine
from core.prevention_engine import PreventionEngine
from core.notification_service import NotificationService
from core.classification_system import ClassificationSystem
from ml.model_loader import ModelLoader
from utils.email_sender import EmailSender
from utils.ddos_logger import log_attack, get_recent_attacks, get_all_attack_ips, update_ip_blocked_status
from ui.app import run_webapp, register_callbacks, on_attack_detected
from ui.app import update_detection_stats, update_blocked_ips, update_system_info


class DDoSDetectionSystem:
    """
    Main class managing the entire DDoS detection and prevention system.
    """
    
    def __init__(self, config_path: str):
        # Set up logging
        logging.config.fileConfig('config/logging.conf')
        self.logger = logging.getLogger(__name__)
        
        # Load configuration
        self.config = configparser.ConfigParser()
        self.config.read(config_path)
        
        # Initialize packet queue for communication between components
        self.packet_queue = queue.Queue()
        
        # Initialize system components
        self.prevention_engine = None
        self.packet_capture = None
        self.feature_extractor = None
        self.classification_system = None
        self.detection_engine = None
        self.notification_service = None
        
        # Set up all system components
        self.setup_components()

        # System state
        self.running = False
        self.stats_thread = None
        self.start_time = 0
    
    def setup_components(self):
        """Set up all system components in the correct order."""
        try:
            # First set up prevention engine (independent of other components)
            self._setup_prevention_engine()
            
            # Load ML models
            self._load_models()
            
            # Set up packet capture
            self._setup_packet_capture()
            
            # Set up notification service
            self._setup_notification_service()
            
            # Set up detection engine (depends on models, notification, and prevention)
            self._setup_detection_engine()
            
            # Register callbacks for the web UI
            self._register_ui_callbacks()
            
            self.logger.info("Successfully set up all system components")
            
        except Exception as e:
            self.logger.error(f"Error setting up system components: {e}", exc_info=True)
            raise
    
    def _setup_prevention_engine(self):
        """Set up the prevention engine."""
        try:
            # Get prevention configuration
            block_duration = self.config.getint('Prevention', 'block_duration', fallback=300)
            whitelist_str = self.config.get('Prevention', 'whitelist', fallback='127.0.0.1')
            whitelist = [ip.strip() for ip in whitelist_str.split(',') if ip.strip()]
            auto_block = self.config.getboolean('Prevention', 'auto_block', fallback=True)
            min_alerts = self.config.getint('Prevention', 'min_alerts_for_autoblock', fallback=3)
            alert_window = self.config.getint('Prevention', 'alert_window', fallback=60)
            
            # Get autoblock attack types
            autoblock_types_str = self.config.get('Prevention', 'autoblock_attack_types', fallback='')
            autoblock_types = [t.strip() for t in autoblock_types_str.split(',') if t.strip()]
            
            # Initialize prevention engine
            self.prevention_engine = PreventionEngine(
                block_duration=block_duration,
                whitelist=whitelist,
                auto_block=auto_block,
                min_alerts_for_autoblock=min_alerts,
                alert_window=alert_window,
                auto_block_attack_types=autoblock_types
            )
            
            # Start the prevention engine
            self.prevention_engine.start()
            self.logger.info("Prevention engine initialized and started")
            
        except Exception as e:
            self.logger.error(f"Error setting up prevention engine: {e}", exc_info=True)
            raise
    
    def _load_models(self):
        """Load and prepare ML models."""
        try:
            # Get model paths from config
            primary_model_path = self.config.get('Detection', 'model_path')
            secondary_model_path = self.config.get('Detection', 'secondary_model_path', fallback=None)
            use_secondary_model = self.config.getboolean('Detection', 'use_secondary_model', fallback=True)
            
            model_paths = [primary_model_path]
            if secondary_model_path and use_secondary_model:
                model_paths.append(secondary_model_path)
            
            # Load all models
            model_loader = ModelLoader(model_paths)
            models_info = model_loader.load_all_models()
            
            # Get model weights from config
            weights_str = self.config.get('Detection', 'model_weights', fallback='0.6, 0.4')
            model_weights = [float(w.strip()) for w in weights_str.split(',')]
            
            # Apply weights to models
            for i, model_info in enumerate(models_info):
                if i < len(model_weights):
                    model_info['weight'] = model_weights[i]
                else:
                    model_info['weight'] = 1.0 / len(models_info)
            
            # Initialize classification system
            self.classification_system = ClassificationSystem(models_info, self.config)
            
            # Log model info
            for i, model_info in enumerate(models_info):
                model_type = model_info.get('model_type', 'unknown')
                n_features = len(model_info.get('feature_columns', []))
                self.logger.info(f"Loaded model {i+1}: {model_type} with {n_features} features")
            
        except Exception as e:
            self.logger.error(f"Error loading models: {e}", exc_info=True)
            raise
    
    def _setup_packet_capture(self):
        """Set up the packet capture component."""
        try:
            # Get network configuration
            interface = self.config.get('Network', 'interface')
            capture_filter = self.config.get('Network', 'capture_filter', fallback='ip')
            buffer_size = self.config.getint('Network', 'buffer_size', fallback=1000)
            max_packets_per_flow = self.config.getint('Network', 'max_packets_per_flow', fallback=20)
            
            # Initialize packet capture
            self.packet_capture = PacketCapture(
                interface=interface,
                packet_queue=self.packet_queue,
                capture_filter=capture_filter,
                buffer_size=buffer_size,
                max_packets_per_flow=max_packets_per_flow
            )
            
            # Initialize feature extractors
            self._setup_feature_extractors()
            
            self.logger.info(f"Packet capture initialized on interface {interface}")
            
        except Exception as e:
            self.logger.error(f"Error setting up packet capture: {e}", exc_info=True)
            raise
    
    def _setup_feature_extractors(self):
        """Set up feature extractors for all models."""
        try:
            # Get all required feature sets from the classification system
            feature_extractors = []
            
            # Check if we have models loaded
            if not hasattr(self, 'classification_system') or not self.classification_system:
                self.logger.error("Classification system not initialized, cannot set up feature extractors")
                return
            
            # For each model, create a corresponding feature extractor
            for i, model_info in enumerate(self.classification_system.models):
                model_type = model_info.get('model_type', 'cicddos' if i == 0 else 'suricata')
                feature_columns = model_info.get('feature_columns', [])
                
                self.logger.info(f"Creating feature extractor for {model_type} model with {len(feature_columns)} features")
                
                # Create feature extractor
                feature_extractor = FeatureExtractor(
                    feature_columns=feature_columns,
                    config=self.config,
                    model_type=model_type
                )
                
                feature_extractors.append(feature_extractor)
            
            # Store feature extractors
            self.feature_extractors = feature_extractors
            
            # Set primary feature extractor for backward compatibility
            if feature_extractors:
                self.feature_extractor = feature_extractors[0]
                
            self.logger.info(f"Set up {len(feature_extractors)} feature extractors")
            
        except Exception as e:
            self.logger.error(f"Error setting up feature extractors: {e}", exc_info=True)
            raise
    
    def _setup_notification_service(self):
        """Set up the notification service."""
        try:
            # Get notification configuration
            enable_notifications = self.config.getboolean('Notification', 'enable_notifications', fallback=True)
            if not enable_notifications:
                self.logger.info("Notifications disabled in config")
                return
            
            # Email configuration
            smtp_server = self.config.get('Notification', 'smtp_server')
            smtp_port = self.config.getint('Notification', 'smtp_port')
            sender_email = self.config.get('Notification', 'sender_email')
            password = self.config.get('Notification', 'password')
            recipients_str = self.config.get('Notification', 'recipients')
            recipients = [r.strip() for r in recipients_str.split(',') if r.strip()]
            cooldown_period = self.config.getint('Notification', 'cooldown_period', fallback=300)
            
            # Message format
            message_format = self.config.get('Notification', 'message_format', fallback='html')
            
            # Critical attack types for notifications
            critical_types_str = self.config.get('Notification', 'critical_attack_types', fallback='')
            critical_attack_types = [t.strip() for t in critical_types_str.split(',') if t.strip()]
            
            # Min confidence for notifications
            min_confidence = self.config.getfloat('Notification', 'min_confidence_for_notification', fallback=0.85)
            
            # Set up email sender
            email_config = {
                'smtp_server': smtp_server,
                'smtp_port': smtp_port,
                'sender_email': sender_email,
                'password': password,
                'recipients': recipients
            }
            
            # Initialize notification service
            self.notification_service = NotificationService(
                email_config=email_config,
                cooldown_period=cooldown_period,
                message_format=message_format,
                critical_attack_types=critical_attack_types,
                min_confidence=min_confidence
            )
            
            # Register callback for attack detection
            self.notification_service.register_callback('attack_detected', on_attack_detected)
            
            # Start notification service
            self.notification_service.start()
            
            self.logger.info("Notification service initialized and started")
            
        except Exception as e:
            self.logger.error(f"Error setting up notification service: {e}", exc_info=True)
            self.logger.warning("System will run without notifications")
            self.notification_service = None
    
    def _setup_detection_engine(self):
        """Set up the detection engine."""
        try:
            # Get detection configuration
            detection_threshold = self.config.getfloat('Detection', 'detection_threshold', fallback=0.7)
            check_interval = self.config.getfloat('Detection', 'check_interval', fallback=1.0)
            batch_size = self.config.getint('Detection', 'batch_size', fallback=10)
            
            # Advanced settings
            learning_mode = self.config.getboolean('Advanced', 'learning_mode', fallback=False)
            async_analysis = self.config.getboolean('Advanced', 'async_analysis', fallback=True)
            max_threads = self.config.getint('Advanced', 'max_analysis_threads', fallback=4)
            min_packets = self.config.getint('Advanced', 'min_packets_for_pattern_analysis', fallback=5)
            
            # Get streaming services for false positive reduction
            streaming_services_str = self.config.get('Detection', 'streaming_services', fallback='')
            streaming_services = [s.strip() for s in streaming_services_str.split(',') if s.strip()]
            
            # False positive threshold
            false_positive_threshold = self.config.getfloat('Detection', 'false_positive_threshold', fallback=0.8)
            
            # Determine notification callback
            notification_callback = None
            if self.notification_service:
                notification_callback = self.notification_service.notify
            
            # Initialize detection engine
            self.detection_engine = DetectionEngine(
                classification_system=self.classification_system,
                feature_extractors=self.feature_extractors,
                notification_callback=notification_callback,
                packet_queue=self.packet_queue,
                detection_threshold=detection_threshold,
                check_interval=check_interval,
                batch_size=batch_size,
                config=self.config,
                prevention_engine=self.prevention_engine,
                learning_mode=learning_mode,
                async_analysis=async_analysis,
                max_analysis_threads=max_threads,
                min_packets_for_analysis=min_packets
            )
            
            # Set additional properties
            self.detection_engine.streaming_services = streaming_services
            self.detection_engine.false_positive_threshold = false_positive_threshold
            
            self.logger.info("Detection engine initialized")
            
        except Exception as e:
            self.logger.error(f"Error setting up detection engine: {e}", exc_info=True)
            raise
    
    def _register_ui_callbacks(self):
        """Register callbacks for the web UI."""
        callbacks = {
            'start_detection_callback': self.start_detection,
            'stop_detection_callback': self.stop_detection,
            'start_prevention_callback': self.start_prevention,
            'stop_prevention_callback': self.stop_prevention,
            'block_ip_callback': self.block_ip,
            'unblock_ip_callback': self.unblock_ip,
            'update_config_callback': self.update_config,
            'system': self  # Add the system itself to access other properties
        }
        
        # Register callbacks
        register_callbacks(callbacks)
        self.logger.info("Registered UI callbacks")
    
    def start_all(self) -> bool:
        """Start all system components."""
        try:
            self.logger.info("Starting DDoS detection and prevention system...")
            
            # Start notification service if not already started
            if self.notification_service and not self.notification_service.running:
                self.notification_service.start()
            
            # Start prevention engine if not already started
            if self.prevention_engine and not self.prevention_engine.running:
                self.prevention_engine.start()
            
            # Start stats update thread
            self.running = True
            self.start_time = time.time()
            self.stats_thread = threading.Thread(target=self._update_stats_loop)
            self.stats_thread.daemon = True
            self.stats_thread.start()
            
            self.logger.info("System started successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting system: {e}", exc_info=True)
            self.stop_all()
            return False
    
    def stop_all(self) -> bool:
        """Stop all system components."""
        try:
            self.logger.info("Stopping DDoS detection and prevention system...")
            
            # Stop stats update thread
            self.running = False
            if self.stats_thread and self.stats_thread.is_alive():
                self.stats_thread.join(timeout=2.0)
            
            # Stop components in reverse order
            if hasattr(self, 'detection_engine') and self.detection_engine:
                self.detection_engine.stop_detection()
            
            if hasattr(self, 'packet_capture') and self.packet_capture:
                self.packet_capture.stop_capture()
            
            if hasattr(self, 'prevention_engine') and self.prevention_engine:
                self.prevention_engine.stop()
            
            if hasattr(self, 'notification_service') and self.notification_service:
                self.notification_service.stop()
            
            self.logger.info("System stopped successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping system: {e}", exc_info=True)
            return False
    
    def start_detection(self) -> bool:
        """Start the detection components."""
        try:
            # Start packet capture if not already running
            if self.packet_capture and not self.packet_capture.running:
                self.packet_capture.start_capture()
            
            # Start detection engine
            if self.detection_engine:
                self.detection_engine.start_detection()
                self.logger.info("Detection components started")
                return True
            
            self.logger.error("Detection engine not initialized")
            return False
            
        except Exception as e:
            self.logger.error(f"Error starting detection: {e}", exc_info=True)
            return False
    
    def stop_detection(self) -> bool:
        """Stop the detection components."""
        try:
            # Stop detection engine
            if self.detection_engine:
                self.detection_engine.stop_detection()
            
            # Stop packet capture
            if self.packet_capture and self.packet_capture.running:
                self.packet_capture.stop_capture()
            
            self.logger.info("Detection components stopped")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping detection: {e}", exc_info=True)
            return False
    
    def start_prevention(self) -> bool:
        """Start the prevention engine."""
        try:
            if self.prevention_engine:
                self.prevention_engine.start()
                self.logger.info("Prevention engine started")
                return True
            
            self.logger.error("Prevention engine not initialized")
            return False
            
        except Exception as e:
            self.logger.error(f"Error starting prevention: {e}", exc_info=True)
            return False
    
    def stop_prevention(self) -> bool:
        """Stop the prevention engine."""
        try:
            if self.prevention_engine:
                self.prevention_engine.stop()
                self.logger.info("Prevention engine stopped")
                return True
            
            self.logger.error("Prevention engine not initialized")
            return False
            
        except Exception as e:
            self.logger.error(f"Error stopping prevention: {e}", exc_info=True)
            return False
    
    def block_ip(self, ip: str, attack_info: Dict[str, Any] = None) -> bool:
        """Manually block an IP address."""
        try:
            if not self.prevention_engine:
                self.logger.error("Prevention engine not initialized")
                return False
                
            attack_type = "Manual Block"
            confidence = 1.0
            
            if attack_info:
                attack_type = attack_info.get('attack_type', attack_type)
                confidence = attack_info.get('confidence', confidence)
            
            # Block the IP
            result = self.prevention_engine.block_ip(ip, attack_type, confidence)
            
            # Update UI
            update_blocked_ips(self.prevention_engine.get_blocked_ips())
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error blocking IP {ip}: {e}", exc_info=True)
            return False
    
    def unblock_ip(self, ip: str) -> bool:
        """Manually unblock an IP address."""
        try:
            if not self.prevention_engine:
                self.logger.error("Prevention engine not initialized")
                return False
            
            # Unblock the IP
            result = self.prevention_engine.unblock_ip(ip)
            
            # Update UI
            update_blocked_ips(self.prevention_engine.get_blocked_ips())
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error unblocking IP {ip}: {e}", exc_info=True)
            return False
    
    def update_config(self, config_data: Dict[str, Any]) -> bool:
        """Update system configuration."""
        try:
            section = config_data.get('section', '').lower()
            config = config_data.get('config', {})
            
            # Track component status for restart
            component_status = {
                'detection': {'running': False, 'restarted': False},
                'prevention': {'running': False, 'restarted': False},
                'notification': {'running': False, 'restarted': False}
            }
            
            # Save current state
            if hasattr(self, 'detection_engine') and self.detection_engine:
                component_status['detection']['running'] = self.detection_engine.is_running
            
            if hasattr(self, 'prevention_engine') and self.prevention_engine:
                component_status['prevention']['running'] = self.prevention_engine.running
            
            if hasattr(self, 'notification_service') and self.notification_service:
                component_status['notification']['running'] = self.notification_service.running
            
            # Update configuration based on section
            if section == 'detection':
                self._update_detection_config(config, component_status)
            elif section == 'network':
                self._update_network_config(config, component_status)
            elif section == 'prevention':
                self._update_prevention_config(config, component_status)
            elif section == 'notification':
                self._update_notification_config(config, component_status)
            elif section == 'advanced':
                self._update_advanced_config(config, component_status)
            else:
                self.logger.warning(f"Unknown configuration section: {section}")
            
            # Restart components if needed
            if component_status['detection']['restarted'] and component_status['detection']['running']:
                self.logger.info("Restarting detection engine with new configuration...")
                self.start_detection()
            
            if component_status['prevention']['restarted'] and component_status['prevention']['running']:
                self.logger.info("Restarting prevention engine with new configuration...")
                self.start_prevention()
            
            if component_status['notification']['restarted'] and component_status['notification']['running']:
                self.logger.info("Restarting notification service with new configuration...")
                self.notification_service.start()
            
            # Save configuration to file
            self._save_config_to_file(section, config)
            
            # Update UI
            update_blocked_ips(self.prevention_engine.get_blocked_ips())
            update_detection_stats(self.detection_engine.get_detection_stats())
            update_system_info(self._get_system_info())
            
            self.logger.info(f"Configuration updated for section: {section}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error updating configuration: {e}", exc_info=True)
            return False
    
    def _update_detection_config(self, config: Dict[str, Any], component_status: Dict[str, Dict[str, bool]]):
        """Update detection configuration."""
        need_restart = False
        
        # Parameters requiring restart
        restart_params = ['batch_size', 'model_path', 'secondary_model_path', 'use_secondary_model']
        for param in restart_params:
            if param in config:
                need_restart = True
                break
        
        # Stop detection if needed
        if need_restart and component_status['detection']['running']:
            self.logger.info("Stopping detection components to apply configuration changes...")
            self.detection_engine.stop_detection()
            if self.packet_capture.running:
                self.packet_capture.stop_capture()
            component_status['detection']['restarted'] = True
        
        # Update parameters not requiring restart
        if 'detection_threshold' in config:
            self.detection_engine.detection_threshold = float(config['detection_threshold'])
            self.logger.info(f"Updated detection threshold: {config['detection_threshold']}")
        
        if 'check_interval' in config:
            self.detection_engine.check_interval = float(config['check_interval'])
            self.logger.info(f"Updated check interval: {config['check_interval']}")
        
        # Update streaming services list
        if 'streaming_services' in config and isinstance(config['streaming_services'], list):
            self.detection_engine.streaming_services = config['streaming_services']
            self.logger.info(f"Updated streaming services list: {len(config['streaming_services'])} services")
        
        # Update false positive threshold
        if 'false_positive_threshold' in config:
            self.detection_engine.false_positive_threshold = float(config['false_positive_threshold'])
            self.logger.info(f"Updated false positive threshold: {config['false_positive_threshold']}")
        
        # Handle parameters requiring restart
        if need_restart:
            # Reload models if model paths changed
            if 'model_path' in config or 'secondary_model_path' in config or 'use_secondary_model' in config:
                self._load_models()
                self._setup_feature_extractors()
                self._setup_detection_engine()
            
            # Update batch size
            if 'batch_size' in config:
                self.detection_engine.batch_size = int(config['batch_size'])
                self.logger.info(f"Updated batch size: {config['batch_size']}")
    
    def _update_network_config(self, config: Dict[str, Any], component_status: Dict[str, Dict[str, bool]]):
        """Update network configuration."""
        need_restart = False
        
        # Parameters requiring restart
        network_restart_params = ['interface', 'capture_filter']
        for param in network_restart_params:
            if param in config:
                need_restart = True
                break
        
        # Stop detection if needed
        if need_restart and component_status['detection']['running']:
            self.logger.info("Stopping detection components to apply network configuration changes...")
            self.detection_engine.stop_detection()
            if self.packet_capture.running:
                self.packet_capture.stop_capture()
            component_status['detection']['restarted'] = True
        
        # Update network configuration
        if 'interface' in config or 'capture_filter' in config:
            # Get new values or use existing ones
            interface = config.get('interface', self.packet_capture.interface)
            capture_filter = config.get('capture_filter', self.packet_capture.capture_filter)
            
            # Recreate packet capture if needed
            if interface != self.packet_capture.interface or capture_filter != self.packet_capture.capture_filter:
                buffer_size = self.packet_capture.buffer_size
                max_packets = self.packet_capture.max_packets_per_flow
                
                self.packet_capture = PacketCapture(
                    interface=interface,
                    packet_queue=self.packet_queue,
                    capture_filter=capture_filter,
                    buffer_size=buffer_size,
                    max_packets_per_flow=max_packets
                )
                
                self.logger.info(f"Updated network configuration: interface={interface}, filter={capture_filter}")
    
    def _update_prevention_config(self, config: Dict[str, Any], component_status: Dict[str, Dict[str, bool]]):
        """Update prevention configuration."""
        need_restart = False
        
        # Parameters requiring restart
        if 'auto_block' in config:
            need_restart = True
        
        # Stop prevention if needed
        if need_restart and component_status['prevention']['running']:
            self.logger.info("Stopping prevention engine to apply configuration changes...")
            self.prevention_engine.stop()
            component_status['prevention']['restarted'] = True
        
        # Update parameters
        if 'whitelist' in config and isinstance(config['whitelist'], list):
            self.prevention_engine.whitelist = set(config['whitelist'])
            self.logger.info(f"Updated IP whitelist: {len(config['whitelist'])} IPs")
        
        if 'block_duration' in config:
            self.prevention_engine.block_duration = int(config['block_duration'])
            self.logger.info(f"Updated block duration: {config['block_duration']} seconds")
        
        if 'min_alerts_for_autoblock' in config:
            self.prevention_engine.min_alerts_for_autoblock = int(config['min_alerts_for_autoblock'])
            self.logger.info(f"Updated minimum alerts for autoblock: {config['min_alerts_for_autoblock']}")
        
        if 'alert_window' in config:
            self.prevention_engine.alert_window = int(config['alert_window'])
            self.logger.info(f"Updated alert window: {config['alert_window']} seconds")
        
        if 'auto_block' in config:
            self.prevention_engine.auto_block = bool(config['auto_block'])
            self.logger.info(f"Updated auto-block setting: {config['auto_block']}")
    
    def _update_notification_config(self, config: Dict[str, Any], component_status: Dict[str, Dict[str, bool]]):
        """Update notification configuration."""
        need_restart = False
        
        # Parameters requiring restart
        if 'enable_notifications' in config:
            need_restart = True
        
        # Stop notification service if needed
        if need_restart and component_status['notification']['running'] and self.notification_service:
            self.logger.info("Stopping notification service to apply configuration changes...")
            self.notification_service.stop()
            component_status['notification']['restarted'] = True
        
        # Update email configuration
        if all(k in config for k in ['smtp_server', 'smtp_port', 'sender_email']):
            # Create new email config
            email_config = {
                'smtp_server': config['smtp_server'],
                'smtp_port': int(config['smtp_port']),
                'sender_email': config['sender_email'],
                'password': config.get('password', self.notification_service.email_sender.password),
                'recipients': config.get('recipients', self.notification_service.email_sender.recipients)
            }
            
            # Update email sender
            if self.notification_service:
                self.notification_service.email_sender = EmailSender(**email_config)
                self.logger.info("Updated email configuration")
        
                # Update cooldown period
        if 'cooldown_period' in config and self.notification_service:
            self.notification_service.cooldown_period = int(config['cooldown_period'])
            self.logger.info(f"Updated notification cooldown period: {config['cooldown_period']} seconds")
            
        # Update recipient list
        if 'recipients' in config and isinstance(config['recipients'], list) and self.notification_service:
            self.notification_service.email_sender.recipients = config['recipients']
            self.logger.info(f"Updated notification recipients: {len(config['recipients'])} addresses")
        
        # Update message format
        if 'message_format' in config and self.notification_service:
            self.notification_service.message_format = config['message_format']
            self.logger.info(f"Updated notification message format: {config['message_format']}")
            
        # Update minimum confidence for notifications
        if 'min_confidence_for_notification' in config and self.notification_service:
            self.notification_service.min_confidence = float(config['min_confidence_for_notification'])
            self.logger.info(f"Updated minimum confidence for notifications: {config['min_confidence_for_notification']}")
    
    def _update_advanced_config(self, config: Dict[str, Any], component_status: Dict[str, Dict[str, bool]]):
        """Update advanced configuration."""
        need_restart = False
        
        # Parameters requiring restart
        restart_params = ['async_analysis', 'max_analysis_threads']
        for param in restart_params:
            if param in config:
                need_restart = True
                break
        
        # Stop detection if needed
        if need_restart and component_status['detection']['running']:
            self.logger.info("Stopping detection engine to apply advanced configuration changes...")
            self.detection_engine.stop_detection()
            component_status['detection']['restarted'] = True
        
        # Update parameters
        if 'learning_mode' in config and self.detection_engine:
            self.detection_engine.learning_mode = bool(config['learning_mode'])
            self.logger.info(f"Updated learning mode: {config['learning_mode']}")
        
        if 'detailed_traffic_logging' in config:
            # This would affect logging configuration
            pass
        
        if 'data_retention_days' in config:
            # This would affect data cleanup processes
            pass
        
        if 'async_analysis' in config and self.detection_engine:
            self.detection_engine.async_analysis = bool(config['async_analysis'])
            self.logger.info(f"Updated async analysis: {config['async_analysis']}")
        
        if 'max_analysis_threads' in config and self.detection_engine:
            self.detection_engine.max_analysis_threads = int(config['max_analysis_threads'])
            self.logger.info(f"Updated max analysis threads: {config['max_analysis_threads']}")
        
        if 'min_packets_for_pattern_analysis' in config and self.detection_engine:
            self.detection_engine.min_packets_for_analysis = int(config['min_packets_for_pattern_analysis'])
            self.logger.info(f"Updated min packets for pattern analysis: {config['min_packets_for_pattern_analysis']}")
        
        if 'multi_model_analysis' in config and self.detection_engine:
            # This would affect the classification system behavior
            pass
    
    def _save_config_to_file(self, section: str, config: Dict[str, Any]):
        """Save configuration to config.ini file."""
        try:
            # Map section name to standard format
            section_map = {
                'detection': 'Detection',
                'prevention': 'Prevention',
                'notification': 'Notification',
                'network': 'Network',
                'webui': 'WebUI',
                'advanced': 'Advanced'
            }
            
            section_name = section_map.get(section.lower(), section.capitalize())
            
            # Read current config file
            config_path = 'config/config.ini'
            config_parser = configparser.ConfigParser()
            config_parser.read(config_path)
            
            # Ensure section exists
            if section_name not in config_parser:
                config_parser[section_name] = {}
            
            # Update values
            for key, value in config.items():
                # Handle special data types
                if isinstance(value, list):
                    config_parser[section_name][key] = ', '.join(str(item) for item in value)
                elif isinstance(value, bool):
                    config_parser[section_name][key] = str(value).lower()
                else:
                    config_parser[section_name][key] = str(value)
            
            # Save file
            with open(config_path, 'w') as f:
                config_parser.write(f)
                
            self.logger.info(f"Saved configuration to {config_path}")
                
        except Exception as e:
            self.logger.error(f"Error saving configuration to file: {e}", exc_info=True)
    
    def _update_stats_loop(self):
        """Thread to periodically update system statistics for the UI."""
        while self.running:
            try:
                # Update detection statistics
                if self.detection_engine:
                    detection_stats = self.detection_engine.get_detection_stats()
                    update_detection_stats(detection_stats)
                
                # Update blocked IP list
                if self.prevention_engine:
                    blocked_ips = self.prevention_engine.get_blocked_ips()
                    update_blocked_ips(blocked_ips)
                
                # Update system information
                system_info = self._get_system_info()
                update_system_info(system_info)
                
            except Exception as e:
                self.logger.error(f"Error updating statistics: {e}", exc_info=True)
                
            time.sleep(5)  # Update every 5 seconds
    
    def _get_system_info(self) -> Dict[str, Any]:
        """
        Collect system information for the UI.
        
        Returns:
            Dict with system information
        """
        return {
            'cpu_percent': psutil.cpu_percent(),
            'memory_percent': psutil.virtual_memory().percent,
            'packet_queue_size': self.packet_queue.qsize() if self.packet_queue else 0,
            'uptime': time.time() - self.start_time if self.start_time > 0 else 0,
            'detection_running': self.detection_engine.is_running if self.detection_engine else False,
            'prevention_running': self.prevention_engine.running if self.prevention_engine else False,
            'active_connections': len(self.packet_capture.flow_table) if self.packet_capture else 0
        }
    
    def run(self):
        """Start the system and run the web UI."""
        try:
            # Display information about streaming services
            if hasattr(self, 'detection_engine') and hasattr(self.detection_engine, 'streaming_services'):
                streaming_services = ', '.join(self.detection_engine.streaming_services)
                self.logger.info(f"Automatic detection support for streaming services: {streaming_services}")
            
            # Start system components
            if not self.start_all():
                self.logger.error("Failed to start system. Exiting.")
                return
            
            # Start detection if configured to auto-start
            auto_start_detection = self.config.getboolean('Detection', 'auto_start', fallback=True)
            if auto_start_detection:
                self.start_detection()
                self.logger.info("Auto-started detection engine")
            
            # Run web UI
            host = self.config.get('WebUI', 'host', fallback='0.0.0.0')
            port = self.config.getint('WebUI', 'port', fallback=5000)
            debug = self.config.getboolean('WebUI', 'debug', fallback=False)
            
            self.logger.info(f"Starting web UI at http://{host}:{port}")
            run_webapp(host, port, debug)
            
        except KeyboardInterrupt:
            self.logger.info("Received exit signal. Stopping system...")
            self.stop_all()
        except Exception as e:
            self.logger.critical(f"Unhandled error: {e}", exc_info=True)
            self.stop_all()


if __name__ == "__main__":
    # Default config path
    config_path = "config/config.ini"
    
    # Allow specifying config path via command line
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
    
    # Initialize and run system
    system = DDoSDetectionSystem(config_path)
    system.run()