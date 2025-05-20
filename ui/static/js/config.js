// src/ddos_detection_system/ui/static/js/config.js

// Cập nhật hiển thị ngưỡng phát hiện khi di chuyển thanh trượt
document.getElementById('detection_threshold').addEventListener('input', function() {
    document.getElementById('threshold_value').textContent = this.value;
});

// Tải cấu hình hiện tại
function loadCurrentConfig() {
    fetch('/api/status')
        .then(response => response.json())
        .then(data => {
            updateSystemStatusIndicator(data);
            
            // Điều chỉnh nút bắt đầu/dừng phát hiện
            const detectionToggle = document.getElementById('detection-toggle');
            if (data.detection_running) {
                detectionToggle.classList.remove('btn-success');
                detectionToggle.classList.add('btn-danger');
                detectionToggle.innerHTML = '<i class="bi bi-stop-fill me-1"></i>Dừng phát hiện';
            } else {
                detectionToggle.classList.remove('btn-danger');
                detectionToggle.classList.add('btn-success');
                detectionToggle.innerHTML = '<i class="bi bi-play-fill me-1"></i>Bắt đầu phát hiện';
            }
            
            // Điều chỉnh nút bắt đầu/dừng ngăn chặn
            const preventionToggle = document.getElementById('prevention-toggle');
            if (data.prevention_running) {
                preventionToggle.classList.remove('btn-success');
                preventionToggle.classList.add('btn-danger');
                preventionToggle.innerHTML = '<i class="bi bi-stop-fill me-1"></i>Dừng ngăn chặn';
            } else {
                preventionToggle.classList.remove('btn-danger');
                preventionToggle.classList.add('btn-success');
                preventionToggle.innerHTML = '<i class="bi bi-play-fill me-1"></i>Bắt đầu ngăn chặn';
            }
        })
        .catch(error => {
            console.error('Lỗi khi tải trạng thái hệ thống:', error);
        });
        
    // Tải cấu hình từ server
    fetch('/api/get_config')
        .then(response => response.json())
        .then(config => {
            // Điền giá trị vào form
            if (config.detection) {
                document.getElementById('detection_threshold').value = config.detection.detection_threshold || 0.7;
                document.getElementById('threshold_value').textContent = config.detection.detection_threshold || 0.7;
                document.getElementById('batch_size').value = config.detection.batch_size || 5;
                document.getElementById('check_interval').value = config.detection.check_interval || 1.0;
            }
            
            if (config.prevention) {
                document.getElementById('block_duration').value = config.prevention.block_duration || 300;
                document.getElementById('whitelist').value = Array.isArray(config.prevention.whitelist) ? 
                    config.prevention.whitelist.join(', ') : config.prevention.whitelist || '';
                document.getElementById('enable_auto_block').checked = config.prevention.enable_auto_block !== false;
            }
            
            if (config.notification) {
                document.getElementById('smtp_server').value = config.notification.smtp_server || '';
                document.getElementById('smtp_port').value = config.notification.smtp_port || '';
                document.getElementById('sender_email').value = config.notification.sender_email || '';
                document.getElementById('email_password').value = ''; // Không hiển thị mật khẩu
                document.getElementById('recipients').value = Array.isArray(config.notification.recipients) ?
                    config.notification.recipients.join(', ') : config.notification.recipients || '';
                document.getElementById('cooldown_period').value = config.notification.cooldown_period || 300;
                document.getElementById('enable_notifications').checked = config.notification.enable_notifications !== false;
            }
        })
        .catch(error => {
            console.error('Lỗi khi tải cấu hình:', error);
        });
}

// Cập nhật trạng thái hệ thống
function updateSystemStatusIndicator(data) {
    const indicator = document.getElementById('system-status-indicator');
    let html = '';
    
    if (data.detection_running) {
        html += '<span class="status-indicator status-active"></span>';
        html += '<span class="text-success fw-bold">Phát hiện: Hoạt động</span>';
    } else {
        html += '<span class="status-indicator status-inactive"></span>';
        html += '<span class="text-danger fw-bold">Phát hiện: Dừng</span>';
    }
    
    html += ' | ';
    
    if (data.prevention_running) {
        html += '<span class="status-indicator status-active"></span>';
        html += '<span class="text-success fw-bold">Ngăn chặn: Hoạt động</span>';
    } else {
        html += '<span class="status-indicator status-inactive"></span>';
        html += '<span class="text-danger fw-bold">Ngăn chặn: Dừng</span>';
    }
    
    indicator.innerHTML = html;
}

// Xử lý form Detection
document.getElementById('detection-form').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const config = {
        detection_threshold: parseFloat(document.getElementById('detection_threshold').value),
        batch_size: parseInt(document.getElementById('batch_size').value),
        check_interval: parseFloat(document.getElementById('check_interval').value)
    };
    
    updateConfig('detection', config);
});

// Xử lý form Prevention
document.getElementById('prevention-form').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const whitelist = document.getElementById('whitelist').value
        .split(',')
        .map(ip => ip.trim())
        .filter(ip => ip);
    
    const config = {
        block_duration: parseInt(document.getElementById('block_duration').value),
        whitelist: whitelist,
        enable_auto_block: document.getElementById('enable_auto_block').checked
    };
    
    updateConfig('prevention', config);
});

// Xử lý form Notification
document.getElementById('notification-form').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const recipients = document.getElementById('recipients').value
        .split(',')
        .map(email => email.trim())
        .filter(email => email);
    
    const config = {
        smtp_server: document.getElementById('smtp_server').value,
        smtp_port: parseInt(document.getElementById('smtp_port').value),
        sender_email: document.getElementById('sender_email').value,
        password: document.getElementById('email_password').value,
        recipients: recipients,
        cooldown_period: parseInt(document.getElementById('cooldown_period').value),
        enable_notifications: document.getElementById('enable_notifications').checked
    };
    
    updateConfig('notification', config);
});

// Cập nhật cấu hình
function updateConfig(section, config) {
    fetch('/api/update_config', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            section: section,
            config: config
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert(`Cấu hình ${section} đã được cập nhật thành công!`);
        } else {
            alert(`Lỗi khi cập nhật cấu hình ${section}: ${data.error || 'Lỗi không xác định'}`);
        }
    })
    .catch(error => {
        console.error('Lỗi khi cập nhật cấu hình:', error);
        alert('Đã xảy ra lỗi khi cập nhật cấu hình');
    });
}

// Xử lý nút bắt đầu/dừng phát hiện
document.getElementById('detection-toggle').addEventListener('click', function() {
    const isRunning = this.classList.contains('btn-danger');
    
    if (isRunning) {
        // Dừng phát hiện
        fetch('/api/stop_detection', {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                this.classList.remove('btn-danger');
                this.classList.add('btn-success');
                this.innerHTML = '<i class="bi bi-play-fill me-1"></i>Bắt đầu phát hiện';
                loadCurrentConfig();
            } else {
                alert(`Không thể dừng phát hiện: ${data.error || 'Lỗi không xác định'}`);
            }
        })
        .catch(error => {
            console.error('Lỗi khi dừng phát hiện:', error);
        });
    } else {
        // Bắt đầu phát hiện
        fetch('/api/start_detection', {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                this.classList.remove('btn-success');
                this.classList.add('btn-danger');
                this.innerHTML = '<i class="bi bi-stop-fill me-1"></i>Dừng phát hiện';
                loadCurrentConfig();
            } else {
                alert(`Không thể bắt đầu phát hiện: ${data.error || 'Lỗi không xác định'}`);
            }
        })
        .catch(error => {
            console.error('Lỗi khi bắt đầu phát hiện:', error);
        });
    }
});

// Xử lý nút bắt đầu/dừng ngăn chặn
document.getElementById('prevention-toggle').addEventListener('click', function() {
    const isRunning = this.classList.contains('btn-danger');
    
    if (isRunning) {
        // Dừng ngăn chặn
        fetch('/api/stop_prevention', {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                this.classList.remove('btn-danger');
                this.classList.add('btn-success');
                this.innerHTML = '<i class="bi bi-play-fill me-1"></i>Bắt đầu ngăn chặn';
                loadCurrentConfig();
            } else {
                alert(`Không thể dừng ngăn chặn: ${data.error || 'Lỗi không xác định'}`);
            }
        })
        .catch(error => {
            console.error('Lỗi khi dừng ngăn chặn:', error);
        });
    } else {
        // Bắt đầu ngăn chặn
        fetch('/api/start_prevention', {
            method: 'POST'
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                this.classList.remove('btn-success');
                this.classList.add('btn-danger');
                this.innerHTML = '<i class="bi bi-stop-fill me-1"></i>Dừng ngăn chặn';
                loadCurrentConfig();
            } else {
                alert(`Không thể bắt đầu ngăn chặn: ${data.error || 'Lỗi không xác định'}`);
            }
        })
        .catch(error => {
            console.error('Lỗi khi bắt đầu ngăn chặn:', error);
        });
    }
});

// Xử lý nút kiểm tra email
document.getElementById('test-email').addEventListener('click', function() {
    this.disabled = true;
    this.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Đang gửi...';
    
    fetch('/api/test_email', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            smtp_server: document.getElementById('smtp_server').value,
            smtp_port: parseInt(document.getElementById('smtp_port').value),
            sender_email: document.getElementById('sender_email').value,
            password: document.getElementById('email_password').value,
            recipients: document.getElementById('recipients').value.split(',').map(e => e.trim()).filter(e => e)
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Email kiểm tra đã được gửi thành công!');
        } else {
            alert(`Không thể gửi email kiểm tra: ${data.error || 'Lỗi không xác định'}`);
        }
    })
    .catch(error => {
        console.error('Lỗi khi gửi email kiểm tra:', error);
        alert('Đã xảy ra lỗi khi gửi email kiểm tra');
    })
    .finally(() => {
        this.disabled = false;
        this.innerHTML = '<i class="bi bi-envelope-check me-1"></i>Kiểm tra email';
    });
});

// Tải cấu hình khi trang được tải
loadCurrentConfig();