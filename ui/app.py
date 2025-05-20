# src/ddos_detection_system/ui/app.py
from flask import Flask, render_template, jsonify, request, redirect, url_for, send_file
import threading
import time
import logging
from typing import Dict, List, Any
import json

app = Flask(__name__)

# Trạng thái và thống kê hệ thống
system_state = {
    'detection_running': False,
    'prevention_running': False,
    'notification_running': False,
    'last_attack_time': None,
    'active_attacks': [],
    'blocked_ips': [],
    'detection_stats': {},
    'system_info': {}
}

# Thêm ở đầu file để tắt thông báo debug

log = logging.getLogger('werkzeug')
log.setLevel(logging.WARNING)

# Lock để đồng bộ hóa truy cập vào system_state
state_lock = threading.Lock()

# Hàm cập nhật trạng thái
def update_system_state(key: str, value: Any):
    with state_lock:
        system_state[key] = value

# Hàm callback khi phát hiện tấn công
def on_attack_detected(attack_info: Dict[str, Any]):
    with state_lock:
        system_state['last_attack_time'] = time.time()
        
        # Thêm tấn công vào danh sách tấn công đang hoạt động
        system_state['active_attacks'].append({
            'attack_type': attack_info.get('attack_type', 'Unknown'),
            'confidence': attack_info.get('confidence', 0),
            'flow_key': attack_info.get('flow_key', ''),
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S', 
                                     time.localtime(attack_info.get('timestamp', time.time())))
        })
        
        # Giới hạn số lượng tấn công hiển thị
        if len(system_state['active_attacks']) > 100:
            system_state['active_attacks'] = system_state['active_attacks'][-100:]

# Định nghĩa các API routes

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/config')
def config():
    return render_template('config.html')

@app.route('/logs')
def logs():
    return render_template('logs.html')

# API endpoints

@app.route('/api/status')
def get_status():
    with state_lock:
        return jsonify(system_state)

@app.route('/api/start_detection', methods=['POST'])
def start_detection():
    # Chuyển request đến controller hệ thống thông qua callback
    if hasattr(app, 'start_detection_callback'):
        success = app.start_detection_callback()
        if success:
            update_system_state('detection_running', True)
        return jsonify({'success': success})
    return jsonify({'success': False, 'error': 'Callback not registered'})

@app.route('/api/stop_detection', methods=['POST'])
def stop_detection():
    if hasattr(app, 'stop_detection_callback'):
        success = app.stop_detection_callback()
        if success:
            update_system_state('detection_running', False)
        return jsonify({'success': success})
    return jsonify({'success': False, 'error': 'Callback not registered'})

@app.route('/api/start_prevention', methods=['POST'])
def start_prevention():
    if hasattr(app, 'start_prevention_callback'):
        success = app.start_prevention_callback()
        if success:
            update_system_state('prevention_running', True)
        return jsonify({'success': success})
    return jsonify({'success': False, 'error': 'Callback not registered'})

@app.route('/api/stop_prevention', methods=['POST'])
def stop_prevention():
    if hasattr(app, 'stop_prevention_callback'):
        success = app.stop_prevention_callback()
        if success:
            update_system_state('prevention_running', False)
        return jsonify({'success': success})
    return jsonify({'success': False, 'error': 'Callback not registered'})

@app.route('/api/blocked_ips')
def get_blocked_ips():
    with state_lock:
        return jsonify(system_state['blocked_ips'])

@app.route('/api/unblock_ip', methods=['POST'])
def unblock_ip():
    ip = request.json.get('ip')
    if not ip:
        return jsonify({'success': False, 'error': 'No IP provided'})
        
    if hasattr(app, 'unblock_ip_callback'):
        success = app.unblock_ip_callback(ip)
        return jsonify({'success': success})
    return jsonify({'success': False, 'error': 'Callback not registered'})

@app.route('/api/detection_stats')
def get_detection_stats():
    with state_lock:
        return jsonify(system_state['detection_stats'])

@app.route('/api/update_config', methods=['POST'])
def update_config():
    config_data = request.json
    if not config_data:
        return jsonify({'success': False, 'error': 'No config data provided'})
        
    if hasattr(app, 'update_config_callback'):
        success = app.update_config_callback(config_data)
        return jsonify({'success': success})
    return jsonify({'success': False, 'error': 'Callback not registered'})
@app.route('/api/attack_logs')
def get_attack_logs():
    """API để lấy log tấn công DDoS."""
    log_file = 'logs/ddos_attacks.log'
    
    # Nếu file không tồn tại, trả về danh sách rỗng
    if not os.path.exists(log_file):
        return jsonify([])
    
    # Lọc theo các tham số
    attack_type = request.args.get('attack_type')
    min_confidence = float(request.args.get('min_confidence', 0.5))
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    
    logs = []
    
    with open(log_file, 'r') as f:
        reader = csv.reader(f)
        
        # Bỏ qua header
        header = next(reader, None)
        
        # Đọc các bản ghi
        for row in reader:
            if len(row) >= 8:  # Đảm bảo đủ cột
                timestamp, attack, src_ip, dst_ip, confidence, protocol, packet_rate, byte_rate = row
                
                # Áp dụng bộ lọc
                if attack_type and attack != attack_type:
                    continue
                    
                try:
                    if float(confidence) < min_confidence:
                        continue
                except:
                    pass
                
                if date_from:
                    if timestamp.split(' ')[0] < date_from:
                        continue
                
                if date_to:
                    if timestamp.split(' ')[0] > date_to:
                        continue
                
                logs.append({
                    'timestamp': timestamp,
                    'attack_type': attack,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'confidence': confidence,
                    'protocol': protocol,
                    'packet_rate': packet_rate,
                    'byte_rate': byte_rate
                })
    
    # Trả về kết quả, giới hạn 1000 bản ghi gần nhất
    return jsonify(logs[-1000:])

@app.route('/api/download_logs')
def download_logs():
    """API để tải xuống file log tấn công DDoS."""
    log_file = 'logs/ddos_attacks.log'
    
    if not os.path.exists(log_file):
        return jsonify({'error': 'Log file not found'}), 404
    
    return send_file(log_file, as_attachment=True, download_name='ddos_attacks.csv')

# Hàm đăng ký các callbacks từ controller chính
def register_callbacks(callbacks: Dict[str, callable]):
    for name, callback in callbacks.items():
        setattr(app, name, callback)

# Hàm để cập nhật thống kê phát hiện
def update_detection_stats(stats: Dict[str, Any]):
    update_system_state('detection_stats', stats)

# Hàm để cập nhật danh sách IP bị chặn
def update_blocked_ips(blocked_ips: List[Dict[str, Any]]):
    update_system_state('blocked_ips', blocked_ips)

# Hàm để cập nhật thông
def update_system_info(info: Dict[str, Any]):
    update_system_state('system_info', info)

def run_webapp(host: str = '0.0.0.0', port: int = 5000, debug: bool = False):
    """
    Khởi chạy ứng dụng web Flask.
    
    Args:
        host: Host để chạy ứng dụng web
        port: Port để chạy ứng dụng web
        debug: Chế độ debug
    """
    app.run(host=host, port=port, debug=debug)