# src/ddos_detection_system/ui/app.py
import configparser
import csv
from flask import Flask, render_template, jsonify, request, redirect, url_for, send_file
import threading
import time
import logging
from typing import Dict, List, Any
import json
import os
from utils.email_sender import EmailSender
from utils.ddos_logger import get_all_attack_ips

app = Flask(__name__)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0  # Tắt cache

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
        # Lấy cấu hình hiện tại
        config = configparser.ConfigParser()
        config.read('config/config.ini')
        
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
        
        system_state['current_config'] = current_config
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
    try:
        with state_lock:
            return jsonify(system_state['blocked_ips'])
    except Exception as e:
        app.logger.error(f"Lỗi khi lấy danh sách IP bị chặn: {e}")
        return jsonify({'error': str(e)}), 500
    
# @app.route('/api/block_ip', methods=['POST'])
# def block_ip():
#     """API để chặn một IP."""
#     ip = request.json.get('ip')
#     if not ip:
#         return jsonify({'success': False, 'error': 'No IP provided'})
        
#     if hasattr(app, 'block_ip_callback'):
#         attack_info = {'attack_type': 'Manual', 'confidence': 1.0}
#         success = app.block_ip_callback(ip, attack_info)
#         return jsonify({'success': success})
#     return jsonify({'success': False, 'error': 'Callback not registered'})

# @app.route('/api/unblock_ip', methods=['POST'])
# def unblock_ip():
#     ip = request.json.get('ip')
#     if not ip:
#         return jsonify({'success': False, 'error': 'No IP provided'})
        
#     if hasattr(app, 'unblock_ip_callback'):
#         success = app.unblock_ip_callback(ip)
#         return jsonify({'success': success})
#     return jsonify({'success': False, 'error': 'Callback not registered'})

@app.route('/api/detection_stats')
def get_detection_stats():
    with state_lock:
        return jsonify(system_state['detection_stats'])

# Thêm API để cập nhật cấu hình
@app.route('/api/update_config', methods=['POST'])
def update_config():
    """API để cập nhật cấu hình."""
    try:
        data = request.json
        if not data or 'section' not in data or 'config' not in data:
            return jsonify({'success': False, 'error': 'Invalid request data'}), 400
            
        section = data['section'].capitalize()  # Đảm bảo viết hoa chữ cái đầu tiên
        config_data = data['config']
        
        # Map section name
        section_map = {
            'detection': 'Detection',
            'prevention': 'Prevention',
            'notification': 'Notification',
            'network': 'Network',
            'webui': 'WebUI'
        }
        
        if section.lower() in section_map:
            section = section_map[section.lower()]
        
        # Đọc file cấu hình hiện tại
        config_path = 'config/config.ini'
        config = configparser.ConfigParser()
        config.read(config_path)
        
        # Đảm bảo section tồn tại
        if section not in config:
            config[section] = {}
        
        # Cập nhật các giá trị cấu hình
        for key, value in config_data.items():
            # Xử lý các kiểu dữ liệu đặc biệt
            if isinstance(value, list):
                config[section][key] = ', '.join(value)
            else:
                config[section][key] = str(value)
        
        # Lưu cấu hình mới
        with open(config_path, 'w') as f:
            config.write(f)
        
        # Tải lại cấu hình trong hệ thống
        if hasattr(app, 'update_config_callback'):
            app.update_config_callback(data)
        
        return jsonify({'success': True})
    except Exception as e:
        app.logger.error(f"Lỗi khi cập nhật cấu hình: {e}")
        return jsonify({'success': False, 'error': str(e)})
# Thêm API để lấy cấu hình hiện tại
@app.route('/api/get_config')
def get_config():
    """API để lấy cấu hình hiện tại."""
    try:
        config_path = 'config/config.ini'
        if not os.path.exists(config_path):
            return jsonify({'error': 'Config file not found'}), 404
            
        config = configparser.ConfigParser()
        config.read(config_path)
        
        result = {}
        
        # Danh sách các tham số yêu cầu khởi động lại
        restart_params = {
            'detection': ['batch_size', 'model_path'],
            'prevention': ['enable_auto_block'],
            'notification': ['enable_notifications'],
            'network': ['interface', 'capture_filter']
        }
        
        # Chuyển đổi ConfigParser thành dict
        for section in config.sections():
            section_lower = section.lower()
            result[section_lower] = {
                'params': {},
                'restart_params': restart_params.get(section_lower, [])
            }
            
            for key, value in config[section].items():
                # Xử lý các giá trị đặc biệt
                if key == 'whitelist':
                    result[section_lower]['params'][key] = [ip.strip() for ip in value.split(',') if ip.strip()]
                elif key == 'recipients':
                    result[section_lower]['params'][key] = [email.strip() for email in value.split(',') if email.strip()]
                elif key in ['detection_threshold', 'check_interval']:
                    result[section_lower]['params'][key] = float(value)
                elif key in ['batch_size', 'block_duration', 'smtp_port', 'cooldown_period']:
                    result[section_lower]['params'][key] = int(value)
                else:
                    result[section_lower]['params'][key] = value
        
        return jsonify(result)
    except Exception as e:
        app.logger.error(f"Lỗi khi lấy cấu hình: {e}")
        return jsonify({'error': str(e)}), 500
# Thêm API để kiểm tra email
@app.route('/api/test_email', methods=['POST'])
def test_email():
    """API để kiểm tra cấu hình email."""
    try:
        data = request.json
        
        # Kiểm tra các thông tin bắt buộc
        required_fields = ['smtp_server', 'smtp_port', 'sender_email', 'recipients']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'success': False, 'error': f'Thiếu thông tin: {field}'}), 400
        
        # Tạo email sender tạm thời với cấu hình mới
        from utils.email_sender import EmailSender
        email_sender = EmailSender(
            smtp_server=data['smtp_server'],
            smtp_port=data['smtp_port'],
            sender_email=data['sender_email'],
            password=data['password'],
            recipients=data['recipients']
        )
        
        # Gửi email kiểm tra
        subject = 'Kiểm tra kết nối email từ Hệ thống phát hiện DDoS'
        body = f"""
        <html>
        <body>
            <h2>Kiểm tra kết nối email thành công!</h2>
            <p>Email này xác nhận rằng cấu hình email của bạn hoạt động chính xác.</p>
            <p><strong>Thời gian:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>Cấu hình:</strong></p>
            <ul>
                <li>SMTP Server: {data['smtp_server']}</li>
                <li>SMTP Port: {data['smtp_port']}</li>
                <li>Sender: {data['sender_email']}</li>
                <li>Recipients: {', '.join(data['recipients'])}</li>
            </ul>
            <p>Nếu bạn nhận được email này, bạn có thể lưu cấu hình và tiếp tục sử dụng hệ thống.</p>
        </body>
        </html>
        """
        
        success = email_sender.send_email(subject=subject, body=body, is_html=True)
        
        return jsonify({'success': success})
    except Exception as e:
        app.logger.error(f"Lỗi khi kiểm tra email: {e}")
        return jsonify({'success': False, 'error': str(e)})
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

# Thêm API để lấy danh sách IP tấn công
@app.route('/api/attack_ips')
def get_attack_ips():
    """API để lấy danh sách tất cả các IP tấn công."""
    try:
        # Lọc theo các tham số
        min_attacks = int(request.args.get('min_attacks', 1))
        min_confidence = float(request.args.get('min_confidence', 0.0))
        attack_type = request.args.get('attack_type')
        sort_by = request.args.get('sort_by', 'attack_count')
        sort_order = request.args.get('sort_order', 'desc')
        
        # Lấy danh sách IP
        ip_list = get_all_attack_ips()
        
        # Áp dụng bộ lọc
        filtered_list = []
        for ip_data in ip_list:
            if ip_data['attack_count'] < min_attacks:
                continue
                
            if ip_data['confidence_avg'] < min_confidence:
                continue
                
            if attack_type and attack_type not in ip_data['attack_types']:
                continue
                
            filtered_list.append(ip_data)
        
        # Sắp xếp
        reverse = sort_order.lower() == 'desc'
        if sort_by == 'ip':
            filtered_list.sort(key=lambda x: x['ip'], reverse=reverse)
        elif sort_by == 'first_seen':
            filtered_list.sort(key=lambda x: x['first_seen'], reverse=reverse)
        elif sort_by == 'last_seen':
            filtered_list.sort(key=lambda x: x['last_seen'], reverse=reverse)
        elif sort_by == 'confidence':
            filtered_list.sort(key=lambda x: x['confidence_avg'], reverse=reverse)
        else:  # attack_count
            filtered_list.sort(key=lambda x: x['attack_count'], reverse=reverse)
        
        return jsonify(filtered_list)
    except Exception as e:
        app.logger.error(f"Lỗi khi lấy danh sách IP tấn công: {e}")
        return jsonify({'error': str(e)}), 500

# Thêm API để tải xuống danh sách IP tấn công
@app.route('/api/download_attack_ips')
def download_attack_ips():
    """API để tải xuống danh sách IP tấn công dưới dạng CSV."""
    try:
        ip_log_file = 'logs/ddos_ips.log'
        
        if not os.path.exists(ip_log_file):
            return jsonify({'error': 'IP log file not found'}), 404
        
        return send_file(ip_log_file, as_attachment=True, download_name='ddos_attack_ips.csv')
    except Exception as e:
        app.logger.error(f"Lỗi khi tải xuống danh sách IP tấn công: {e}")
        return jsonify({'error': str(e)}), 500
    
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