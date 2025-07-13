# ui/socketio_events.py

import logging
from flask import request
from flask_socketio import emit, join_room, leave_room

logger = logging.getLogger("ddos_detection_system.ui.socketio_events")

def register_socketio_events(socketio, app):
    """
    Đăng ký tất cả các sự kiện SocketIO.
    
    Args:
        socketio: Instance của SocketIO
        app: Instance của Flask app
    """
    @socketio.on('connect')
    def handle_connect():
        """Xử lý khi client kết nối."""
        logger.info(f"Client connected: {request.sid}")
        
        # Gửi trạng thái hiện tại cho client mới
        from ui.app import system_state
        emit('full_state_update', system_state)
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Xử lý khi client ngắt kết nối."""
        logger.info(f"Client disconnected: {request.sid}")
    
    @socketio.on('subscribe')
    def handle_subscribe(data):
        """Xử lý đăng ký nhận updates từ một channel cụ thể."""
        channels = data.get('channels', [])
        for channel in channels:
            join_room(channel)
            logger.debug(f"Client {request.sid} subscribed to {channel}")
        
        return {'status': 'success', 'subscribed_to': channels}
    
    @socketio.on('unsubscribe')
    def handle_unsubscribe(data):
        """Xử lý hủy đăng ký nhận updates từ một channel cụ thể."""
        channels = data.get('channels', [])
        for channel in channels:
            leave_room(channel)
            logger.debug(f"Client {request.sid} unsubscribed from {channel}")
        
        return {'status': 'success', 'unsubscribed_from': channels}
    
    @socketio.on('test_connection')
    def handle_test_connection(data):
        """Xử lý thông điệp kiểm tra kết nối."""
        logger.debug(f"Received test connection message: {data}")
        return {'status': 'success', 'message': 'SocketIO connection working'}
    
    @socketio.on('request_logs')
    def handle_request_logs(data):
        """Xử lý yêu cầu lấy logs."""
        max_logs = data.get('max_logs', 100)
        level = data.get('level', None)
        source = data.get('source', None)
        keyword = data.get('keyword', None)
        
        # Lấy logs từ hệ thống
        from ui.app import get_logs
        logs = get_logs(max_logs=max_logs, level=level, source=source, keyword=keyword)
        
        emit('logs_data', {'logs': logs})
        
    @socketio.on('request_blocked_ips')
    def handle_request_blocked_ips():
        """Xử lý yêu cầu lấy danh sách IP bị chặn."""
        from ui.app import system_state, state_lock
        
        with state_lock:
            emit('blocked_ips_update', system_state['blocked_ips'])
    
    @socketio.on('request_attack_stats')
    def handle_request_attack_stats():
        """Xử lý yêu cầu lấy thống kê tấn công."""
        from ui.app import system_state, state_lock
        
        with state_lock:
            emit('detection_stats_update', system_state['detection_stats'])