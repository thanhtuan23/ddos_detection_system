# ui/app.py

import os
import time
import queue
import threading
import logging
import configparser
import json
from typing import Dict, Any, List, Optional
from flask import Flask, render_template, jsonify, request, redirect, url_for, send_file
from flask_socketio import SocketIO
from werkzeug.security import check_password_hash, generate_password_hash

# Khởi tạo Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'ddos_detection_secret_key')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Khởi tạo SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")

# State của hệ thống
system_state = {
    'detection_running': False,
    'prevention_running': False,
    'active_attacks': [],
    'blocked_ips': [],
    'system_info': {
        'cpu_percent': 0,
        'memory_percent': 0,
        'packet_queue_size': 0,
        'uptime': 0
    },
    'detection_stats': {
        'total_flows_analyzed': 0,
        'attack_flows_detected': 0,
        'benign_flows_analyzed': 0,
        'attack_types': {},
        'false_positives': 0
    },
    'last_attack_time': 0,
    'current_config': {}
}

# Lock cho thread safety
state_lock = threading.RLock()

# Đường dẫn đến file cấu hình
CONFIG_PATH = "config/config.ini"

# Cập nhật state của hệ thống
def update_system_state(key: str, value: Any):
    with state_lock:
        system_state[key] = value
        # Emit socket event để cập nhật UI
        socketio.emit('state_update', {key: value})

# Cập nhật thông tin hệ thống
def update_system_info(info: Dict[str, Any]):
    with state_lock:
        system_state['system_info'] = info
        socketio.emit('system_info_update', info)

# Cập nhật thống kê phát hiện
def update_detection_stats(stats: Dict[str, Any]):
    with state_lock:
        system_state['detection_stats'] = stats
        socketio.emit('detection_stats_update', stats)

# Cập nhật danh sách IP bị chặn
def update_blocked_ips(ips: List[Dict[str, Any]]):
    with state_lock:
        system_state['blocked_ips'] = ips
        socketio.emit('blocked_ips_update', ips)

# Xử lý khi phát hiện tấn công
def on_attack_detected(attack_info: Dict[str, Any]):
    with state_lock:
        system_state['last_attack_time'] = time.time()
        
        # Thêm tấn công vào danh sách tấn công đang hoạt động
        system_state['active_attacks'].append({
            'attack_type': attack_info.get('attack_type', 'Unknown'),
            'confidence': attack_info.get('confidence', 0),
            'src_ip': attack_info.get('src_ip', 'Unknown'),
            'dst_ip': attack_info.get('dst_ip', 'Unknown'),
            'flow_key': attack_info.get('flow_key', ''),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', 
                                     time.localtime(attack_info.get('timestamp', time.time())))
        })
        
        # Giới hạn số lượng tấn công hiển thị
        if len(system_state['active_attacks']) > 100:
            system_state['active_attacks'] = system_state['active_attacks'][-100:]
        
        # Emit socket event
        socketio.emit('attack_detected', attack_info)
        socketio.emit('active_attacks_update', system_state['active_attacks'])

# Đăng ký callbacks từ hệ thống chính
def register_callbacks(callbacks: Dict[str, callable]):
    for name, callback in callbacks.items():
        setattr(app, name, callback)
    app.logger.info(f"Registered {len(callbacks)} callbacks from main system")

# Routes

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/logs')
def logs():
    return render_template('logs.html')

@app.route('/config')
def config():
    return render_template('config.html')

@app.route('/help')
def help_page():
    return render_template('help.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

# API Endpoints

@app.route('/api/status')
def get_status():
    with state_lock:
        # Lấy cấu hình hiện tại
        config = configparser.ConfigParser()
        config.read(CONFIG_PATH)
        
        # Thêm thông tin cấu hình vào state
        current_config = {}
        
        if 'Detection' in config:
            current_config['detection'] = {
                'detection_threshold': config.getfloat('Detection', 'detection_threshold', fallback=0.7),
                'batch_size': config.getint('Detection', 'batch_size', fallback=5),
                'check_interval': config.getfloat('Detection', 'check_interval', fallback=1.0)
            }
            
        if 'Prevention' in config:
            current_config['prevention'] = {
                'block_duration': config.getint('Prevention', 'block_duration', fallback=300),
                'whitelist': [ip.strip() for ip in config.get('Prevention', 'whitelist', fallback='').split(',') if ip.strip()]
            }
        
        if 'Network' in config:
            current_config['network'] = {
                'interface': config.get('Network', 'interface', fallback='eth0'),
                'capture_filter': config.get('Network', 'capture_filter', fallback='ip')
            }
        
        system_state['current_config'] = current_config
        return jsonify(system_state)

@app.route('/api/config', methods=['GET'])
def get_config():
    try:
        config = configparser.ConfigParser()
        config.read(CONFIG_PATH)
        
        # Convert to dictionary
        config_dict = {section: dict(config[section]) for section in config.sections()}
        
        return jsonify(config_dict)
    except Exception as e:
        app.logger.error(f"Error reading config: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/config', methods=['POST'])
def update_config():
    try:
        config_data = request.json
        
        if not config_data or 'section' not in config_data or 'config' not in config_data:
            return jsonify({'error': 'Invalid configuration data'}), 400
        
        # Call the callback to update configuration
        if hasattr(app, 'update_config_callback'):
            success = app.update_config_callback(config_data)
            return jsonify({'success': success})
        
        return jsonify({'success': False, 'error': 'Callback not registered'}), 500
    except Exception as e:
        app.logger.error(f"Error updating config: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/detection/start', methods=['POST'])
def start_detection():
    if hasattr(app, 'start_detection_callback'):
        success = app.start_detection_callback()
        if success:
            update_system_state('detection_running', True)
        return jsonify({'success': success})
    return jsonify({'success': False, 'error': 'Callback not registered'})

@app.route('/api/detection/stop', methods=['POST'])
def stop_detection():
    if hasattr(app, 'stop_detection_callback'):
        success = app.stop_detection_callback()
        if success:
            update_system_state('detection_running', False)
        return jsonify({'success': success})
    return jsonify({'success': False, 'error': 'Callback not registered'})

@app.route('/api/prevention/start', methods=['POST'])
def start_prevention():
    if hasattr(app, 'start_prevention_callback'):
        success = app.start_prevention_callback()
        if success:
            update_system_state('prevention_running', True)
        return jsonify({'success': success})
    return jsonify({'success': False, 'error': 'Callback not registered'})

@app.route('/api/prevention/stop', methods=['POST'])
def stop_prevention():
    if hasattr(app, 'stop_prevention_callback'):
        success = app.stop_prevention_callback()
        if success:
            update_system_state('prevention_running', False)
        return jsonify({'success': success})
    return jsonify({'success': False, 'error': 'Callback not registered'})

@app.route('/api/ip/block', methods=['POST'])
def block_ip():
    data = request.json
    ip = data.get('ip', '')
    
    if not ip:
        return jsonify({'success': False, 'error': 'IP address is required'})
    
    if hasattr(app, 'block_ip_callback'):
        success = app.block_ip_callback(ip)
        return jsonify({'success': success})
    
    return jsonify({'success': False, 'error': 'Callback not registered'})

@app.route('/api/ip/unblock', methods=['POST'])
def unblock_ip():
    data = request.json
    ip = data.get('ip', '')
    
    if not ip:
        return jsonify({'success': False, 'error': 'IP address is required'})
    
    if hasattr(app, 'unblock_ip_callback'):
        success = app.unblock_ip_callback(ip)
        return jsonify({'success': success})
    
    return jsonify({'success': False, 'error': 'Callback not registered'})

@app.route('/api/ip/blocked', methods=['GET'])
def get_blocked_ips():
    try:
        with state_lock:
            return jsonify(system_state['blocked_ips'])
    except Exception as e:
        app.logger.error(f"Error getting blocked IPs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/attacks/recent', methods=['GET'])
def get_recent_attacks():
    try:
        from utils.ddos_logger import get_recent_attacks
        limit = request.args.get('limit', 100, type=int)
        attacks = get_recent_attacks(limit)
        return jsonify(attacks)
    except Exception as e:
        app.logger.error(f"Error getting recent attacks: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/attacks/ips', methods=['GET'])
def get_attack_ips():
    try:
        from utils.ddos_logger import get_all_attack_ips
        ips = get_all_attack_ips()
        return jsonify(ips)
    except Exception as e:
        app.logger.error(f"Error getting attack IPs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs', methods=['GET'])
def get_logs():
    try:
        max_logs = request.args.get('max_logs', 100, type=int)
        level = request.args.get('level')
        source = request.args.get('source')
        keyword = request.args.get('keyword')
        
        log_files = {
            'system': 'logs/ddos_detection.log',
            'error': 'logs/error.log',
            'attack': 'logs/ddos_attacks.log'
        }
        
        log_source = log_files.get(source, log_files['system'])
        
        logs = []
        if os.path.exists(log_source):
            with open(log_source, 'r') as f:
                lines = f.readlines()
                
                # Filter by keyword if provided
                if keyword:
                    lines = [line for line in lines if keyword.lower() in line.lower()]
                
                # Get the most recent logs
                for line in lines[-max_logs:]:
                    parts = line.strip().split(" - ", 3)
                    if len(parts) >= 3:
                        timestamp = parts[0]
                        log_level = parts[1]
                        message = parts[2] if len(parts) == 3 else parts[3]
                        
                        # Filter by level if provided
                        if level and log_level.lower() != level.lower():
                            continue
                            
                        logs.append({
                            'timestamp': timestamp,
                            'level': log_level,
                            'message': message
                        })
        
        return jsonify(logs)
    except Exception as e:
        app.logger.error(f"Error getting logs: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/logs/download', methods=['GET'])
def download_logs():
    log_type = request.args.get('type', 'attack')
    
    log_files = {
        'system': 'logs/ddos_detection.log',
        'error': 'logs/error.log',
        'attack': 'logs/ddos_attacks.log'
    }
    
    log_file = log_files.get(log_type, log_files['attack'])
    
    if not os.path.exists(log_file):
        return jsonify({'error': 'Log file not found'}), 404
    
    return send_file(log_file, as_attachment=True, download_name=f'{log_type}_logs.log')

@app.route('/api/system/stats', methods=['GET'])
def get_system_stats():
    with state_lock:
        return jsonify({
            'system_info': system_state['system_info'],
            'detection_stats': system_state['detection_stats']
        })

# Khởi động webapp
def run_webapp(host='0.0.0.0', port=5000, debug=False):
    # Đăng ký socketio events
    from ui.socketio_events import register_socketio_events
    register_socketio_events(socketio, app)
    
    # Khởi động server
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)
# Khởi động webapp
def run_webapp(host='0.0.0.0', port=5000, debug=False):
    # Đăng ký socketio events
    from ui.socketio_events import register_socketio_events
    register_socketio_events(socketio, app) 