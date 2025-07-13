# core/detection_engine.py
import time
import queue
import threading
import logging
from typing import Dict, Any, List, Tuple, Optional, Callable
import numpy as np
from concurrent.futures import ThreadPoolExecutor

class DetectionEngine:
    """
    Engine for detecting DDoS attacks using machine learning models.
    """
    
    def __init__(self, classification_system, feature_extractors, notification_callback, packet_queue,
                 detection_threshold=0.7, check_interval=1.0, batch_size=10, config=None,
                 prevention_engine=None, learning_mode=False, async_analysis=True,
                 max_analysis_threads=4, min_packets_for_analysis=5):
        """
        Initialize the detection engine.
        
        Args:
            classification_system: System for classifying flows
            feature_extractors: List of feature extractors
            notification_callback: Callback function for attack notifications
            packet_queue: Queue with flows to analyze
            detection_threshold: Confidence threshold for attack detection
            check_interval: Interval between detection checks (seconds)
            batch_size: Number of flows to analyze in each batch
            config: Configuration object
            prevention_engine: Engine for blocking attacks
            learning_mode: If True, adjust thresholds automatically
            async_analysis: If True, process flows asynchronously
            max_analysis_threads: Maximum number of threads for async analysis
            min_packets_for_analysis: Minimum number of packets to analyze a flow
        """
        self.logger = logging.getLogger("ddos_detection_system.core.detection_engine")
        
        self.classification_system = classification_system
        self.feature_extractors = feature_extractors
        self.notification_callback = notification_callback
        self.packet_queue = packet_queue
        self.detection_threshold = detection_threshold
        self.check_interval = check_interval
        self.batch_size = batch_size
        self.config = config
        self.prevention_engine = prevention_engine
        self.learning_mode = learning_mode
        self.async_analysis = async_analysis
        self.max_analysis_threads = max_analysis_threads
        self.min_packets_for_analysis = min_packets_for_analysis
        
        # Statistics
        self.stats = {
            'total_flows_analyzed': 0,
            'attack_flows_detected': 0,
            'benign_flows_analyzed': 0,
            'alerts_generated': 0,
            'attack_types': {},
            'false_positives': 0,
            'processing_times': [],
            'start_time': 0,
            'last_attack_time': 0
        }
        
        # Active flows being analyzed
        self.active_flows = {}
        
        # Streaming services for false positive reduction
        self.streaming_services = []
        self.false_positive_threshold = 0.8
        
        # State
        self.running = False
        self.is_running = False
        self.detection_thread = None
        self.lock = threading.RLock()
        
        # Thread pool for async analysis
        self.thread_pool = None
        if self.async_analysis:
            self.thread_pool = ThreadPoolExecutor(max_workers=max_analysis_threads)
        
        self.logger.info(f"Detection engine initialized with threshold={detection_threshold}, interval={check_interval}")
    
    def start_detection(self):
        """Start the detection engine in a separate thread."""
        with self.lock:
            if self.running:
                self.logger.warning("Detection engine already running")
                return
            
            self.running = True
            self.is_running = True
            self.stats['start_time'] = time.time()
            
            self.detection_thread = threading.Thread(target=self._detection_loop)
            self.detection_thread.daemon = True
            self.detection_thread.start()
            
            self.logger.info("DDoS detection engine started")
    
    def stop_detection(self):
        """Stop the detection engine."""
        with self.lock:
            if not self.running:
                self.logger.warning("Detection engine not running")
                return
            
            self.running = False
            
            # Wait for thread to terminate
            if self.detection_thread:
                self.detection_thread.join(timeout=2.0)
            
            self.is_running = False
            
            # Shutdown thread pool if async
            if self.thread_pool:
                self.thread_pool.shutdown(wait=False)
            
            self.logger.info("DDoS detection engine stopped")
    
    def is_legitimate_service(self, src_ip, dst_ip, src_port, dst_port, protocol):
        """
        Check if a flow is likely from a legitimate streaming service.
        
        Args:
            src_ip: Source IP
            dst_ip: Destination IP
            src_port: Source port
            dst_port: Destination port
            protocol: Protocol
            
        Returns:
            True if likely legitimate, False otherwise
        """
        # Check for common streaming service ports
        streaming_ports = [1935, 443, 80, 8080, 8443]
        if src_port in streaming_ports or dst_port in streaming_ports:
            # Check if protocol is appropriate
            if protocol == 6 or protocol == 17:  # TCP or UDP
                return True
        
        # Add custom logic for detecting streaming services
        # For example, by IP ranges or domain name checks
        
        return False
    
    def _detection_loop(self):
        """Main detection loop that processes flows from the queue."""
        self.logger.info("Starting detection loop")
        
        while self.running:
            try:
                # Get batch of flows from queue
                flows = []
                flow_keys = set()
                
                # Try to get up to batch_size flows without blocking
                for _ in range(self.batch_size):
                    try:
                        flow = self.packet_queue.get_nowait()
                        
                        # Skip flows with too few packets
                        if flow.get('packets', 0) < self.min_packets_for_analysis:
                            self.packet_queue.task_done()
                            continue
                        
                        flow_key = flow.get('flow_key', '')
                        if flow_key and flow_key not in flow_keys:
                            flows.append(flow)
                            flow_keys.add(flow_key)
                        
                        self.packet_queue.task_done()
                        
                    except queue.Empty:
                        break
                
                # Process flows if any
                if flows:
                    self._process_flows(flows, flow_keys)
                else:
                    # No flows to process, sleep
                    time.sleep(self.check_interval)
                
            except Exception as e:
                self.logger.error(f"Error in detection loop: {e}", exc_info=True)
                time.sleep(1.0)  # Sleep to avoid tight loop on error
    
    def _process_flows(self, flows, flow_keys):
        """
        Process a batch of flows.
        
        Args:
            flows: List of flows to analyze
            flow_keys: Set of flow keys
        """
        if self.async_analysis and self.thread_pool:
            # Process asynchronously
            futures = []
            
            for flow in flows:
                future = self.thread_pool.submit(self.analyze_flow, flow)
                futures.append((future, flow))
            
            # Process results as they complete
            for future, flow in futures:
                try:
                    is_attack, confidence, attack_type, details = future.result()
                    
                    if is_attack and confidence >= self.detection_threshold:
                        self._handle_detected_attack(flow, attack_type, confidence, details)
                    else:
                        self.stats['benign_flows_analyzed'] += 1
                    
                except Exception as e:
                    self.logger.error(f"Error processing flow result: {e}", exc_info=True)
        else:
            # Process sequentially
            for flow in flows:
                try:
                    is_attack, confidence, attack_type, details = self.analyze_flow(flow)
                    
                    if is_attack and confidence >= self.detection_threshold:
                        self._handle_detected_attack(flow, attack_type, confidence, details)
                    else:
                        self.stats['benign_flows_analyzed'] += 1
                        
                except Exception as e:
                    self.logger.error(f"Error analyzing flow: {e}", exc_info=True)
    
    def analyze_flow(self, flow) -> Tuple[bool, float, str, Optional[Dict[str, Any]]]:
        """
        Analyze a flow to detect attacks.
        
        Args:
            flow: Flow data dictionary
            
        Returns:
            Tuple of (is_attack, confidence, attack_type, details)
        """
        start_time = time.time()
        
        try:
            # Classify flow using the classification system
            is_attack, confidence, attack_type, details = self.classification_system.classify_flow(
                flow, self.feature_extractors
            )
            
            # Apply false positive reduction if confidence is borderline
            if is_attack and self.detection_threshold <= confidence < self.false_positive_threshold:
                # Check if this might be a legitimate streaming service
                if self._check_potential_false_positive(flow):
                    self.logger.debug(f"Potential false positive reduced: {flow.get('flow_key', 'unknown')}")
                    is_attack = False
                    self.stats['false_positives'] += 1
            
            # Update statistics
            with self.lock:
                self.stats['total_flows_analyzed'] += 1
                
                # Record processing time
                end_time = time.time()
                processing_time = (end_time - start_time) * 1000  # ms
                self.stats['processing_times'].append(processing_time)
                
                # Limit processing times list size
                if len(self.stats['processing_times']) > 1000:
                    self.stats['processing_times'] = self.stats['processing_times'][-1000:]
            
            return is_attack, confidence, attack_type, details
            
        except Exception as e:
            self.logger.error(f"Error analyzing flow: {e}", exc_info=True)
            return False, 0.0, "Error", None
    
    def _check_potential_false_positive(self, flow) -> bool:
        """
        Check if a flow might be a false positive.
        
        Args:
            flow: Flow data dictionary
            
        Returns:
            True if likely false positive, False otherwise
        """
        # Check for streaming services
        if self.is_legitimate_service(
            flow.get('src_ip', ''), 
            flow.get('dst_ip', ''), 
            flow.get('src_port', 0), 
            flow.get('dst_port', 0), 
            flow.get('protocol', 0)
        ):
            return True
        
        # Check for high-bandwidth but consistent traffic
        if flow.get('packets', 0) > 100:
            # Calculate coefficient of variation of inter-arrival times
            iat = flow.get('inter_arrival_times', [])
            if len(iat) > 10:
                cv = np.std(iat) / np.mean(iat) if np.mean(iat) > 0 else 0
                # Consistent traffic typically has low CV
                if cv < 0.5:
                    return True
        
        return False
    
    def _handle_detected_attack(self, flow, attack_type, confidence, details):
        """
        Handle a detected attack.
        
        Args:
            flow: Flow data dictionary
            attack_type: Type of attack detected
            confidence: Detection confidence
            details: Additional detection details
        """
        with self.lock:
            self.stats['attack_flows_detected'] += 1
            self.stats['last_attack_time'] = time.time()
            
            # Update attack type stats
            if attack_type not in self.stats['attack_types']:
                self.stats['attack_types'][attack_type] = 0
            self.stats['attack_types'][attack_type] += 1
        
        # Log the attack
        flow_key = flow.get('flow_key', 'unknown')
        src_ip = flow.get('src_ip', 'unknown')
        self._log_attack(flow_key, attack_type, confidence, details)
        
        # Check if this attack type should be blocked
        should_block = self._should_block_attack(attack_type, confidence)
        
        # Prepare attack info for notification
        attack_info = {
            'flow_key': flow_key,
            'attack_type': attack_type,
            'confidence': confidence,
            'src_ip': src_ip,
            'dst_ip': flow.get('dst_ip', 'unknown'),
            'src_port': flow.get('src_port', 0),
            'dst_port': flow.get('dst_port', 0),
            'protocol': flow.get('protocol', 0),
            'packet_rate': flow.get('packet_rate', 0),
            'byte_rate': flow.get('byte_rate', 0),
            'timestamp': time.time(),
            'details': details,
            'blocked': False
        }
        
        # Block the attack if needed
        if should_block and self.prevention_engine:
            try:
                # Block the attacker IP
                blocked = self.prevention_engine.block_ip(src_ip, attack_type, confidence)
                attack_info['blocked'] = blocked
                
                if blocked:
                    self.logger.info(f"Blocked IP {src_ip} for {attack_type} attack with confidence {confidence:.2f}")
                
            except Exception as e:
                self.logger.error(f"Error blocking IP {src_ip}: {e}", exc_info=True)
        
        # Send notification
        with self.lock:
            self.stats['alerts_generated'] += 1
            
        if self.notification_callback:
            try:
                self.notification_callback(attack_info)
            except Exception as e:
                self.logger.error(f"Error sending notification: {e}", exc_info=True)
    
    def _should_block_attack(self, attack_type, confidence) -> bool:
        """
        Determine if an attack should be blocked.
        
        Args:
            attack_type: Type of attack
            confidence: Detection confidence
            
        Returns:
            True if should block, False otherwise
        """
        # Check if prevention is enabled
        if not self.prevention_engine or not self.prevention_engine.auto_block:
            return False
        
        # Check if the attack type is in the auto-block list
        if self.prevention_engine.auto_block_attack_types:
            if attack_type not in self.prevention_engine.auto_block_attack_types:
                return False
        
        # Check confidence against threshold (might be higher for blocking)
        block_threshold = self.config.getfloat('Prevention', 'block_confidence_threshold', 
                                              fallback=self.detection_threshold + 0.1)
        if confidence < block_threshold:
            return False
        
        return True
    
    def _log_attack(self, flow_key, attack_type, confidence, details):
        """
        Log a detected attack.
        
        Args:
            flow_key: Flow identifier
            attack_type: Type of attack
            confidence: Detection confidence
            details: Additional attack details
        """
        from utils.ddos_logger import log_attack
        
        # Extract information from details
        src_ip = details.get('src_ip', 'unknown')
        dst_ip = details.get('dst_ip', 'unknown')
        src_port = details.get('src_port', 0)
        dst_port = details.get('dst_port', 0)
        protocol = details.get('protocol', 0)
        packet_rate = details.get('packet_rate', 0)
        byte_rate = details.get('byte_rate', 0)
        
        # Convert protocol to string
        protocol_str = "TCP" if protocol == 6 else "UDP" if protocol == 17 else "ICMP" if protocol == 1 else str(protocol)
        
        # Log to the attack logger
        log_attack({
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S"),
            'flow_key': flow_key,
            'attack_type': attack_type,
            'confidence': confidence,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol_str,
            'packet_rate': packet_rate,
            'byte_rate': byte_rate,
            'blocked': False  # Will be updated if blocked
        })
        
        # Log to standard logger
        self.logger.warning(
            f"Attack detected: {attack_type} from {src_ip}:{src_port} to {dst_ip}:{dst_port} "
            f"protocol={protocol_str} confidence={confidence:.2f} packet_rate={packet_rate:.2f}"
        )
    
    def get_detection_stats(self):
        """
        Get detection engine statistics.
        
        Returns:
            Dict with statistics
        """
        with self.lock:
            stats = self.stats.copy()
            
            # Calculate additional stats
            uptime = time.time() - stats['start_time'] if stats['start_time'] > 0 else 0
            flows_per_second = stats['total_flows_analyzed'] / uptime if uptime > 0 else 0
            attack_percentage = (stats['attack_flows_detected'] / stats['total_flows_analyzed'] * 100 
                                 if stats['total_flows_analyzed'] > 0 else 0)
            avg_processing_time = sum(stats['processing_times']) / len(stats['processing_times']) if stats['processing_times'] else 0
            
            # Add calculated stats
            stats['uptime'] = uptime
            stats['flows_per_second'] = flows_per_second
            stats['attack_percentage'] = attack_percentage
            stats['avg_processing_time_ms'] = avg_processing_time
            stats['queue_size'] = self.packet_queue.qsize()
            
            return stats