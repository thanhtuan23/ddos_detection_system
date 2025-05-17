// Chức năng cập nhật trạng thái hệ thống
function updateSystemStatus() {
    fetch('/api/status')
        .then(response => response.json())
        .then(data => {
            // Cập nhật trạng thái
            const statusHtml = `
                <div class="d-flex justify-content-between">
                    <span>Phát hiện:</span>
                    <span class="badge ${data.detection_running ? 'bg-success' : 'bg-danger'}">
                        ${data.detection_running ? 'Đang chạy' : 'Đã dừng'}
                    </span>
                </div>
                <div class="d-flex justify-content-between mt-2">
                    <span>Ngăn chặn:</span>
                    <span class="badge ${data.prevention_running ? 'bg-success' : 'bg-danger'}">
                        ${data.prevention_running ? 'Đang chạy' : 'Đã dừng'}
                    </span>
                </div>
                <div class="d-flex justify-content-between mt-2">
                    <span>Thông báo:</span>
                    <span class="badge ${data.notification_running ? 'bg-success' : 'bg-danger'}">
                        ${data.notification_running ? 'Đang chạy' : 'Đã dừng'}
                    </span>
                </div>
            `;
            document.getElementById('system-status').innerHTML = statusHtml;

            // Cập nhật thống kê
            if (data.detection_stats) {
                const stats = data.detection_stats;
                const statsHtml = `
                    <div class="d-flex justify-content-between">
                        <span>Số luồng đã phân tích:</span>
                        <span>${stats.total_flows_analyzed || 0}</span>
                    </div>
                    <div class="d-flex justify-content-between mt-2">
                        <span>Tấn công phát hiện:</span>
                        <span>${stats.total_attacks_detected || 0}</span>
                    </div>
                    <div class="d-flex justify-content-between mt-2">
                        <span>Tấn công đang diễn ra:</span>
                        <span>${stats.active_attack_count || 0}</span>
                    </div>
                `;
                document.getElementById('quick-stats').innerHTML = statsHtml;
            } else {
                document.getElementById('quick-stats').innerHTML = '<p>Không có dữ liệu</p>';
            }

            // Cập nhật danh sách tấn công gần đây
            if (data.active_attacks && data.active_attacks.length > 0) {
                let attacksHtml = '<ul class="list-group">';
                data.active_attacks.slice(0, 3).forEach(attack => {
                    attacksHtml += `
                        <li class="list-group-item">
                            <strong>${attack.attack_type}</strong>
                            <br>
                            <small>${attack.timestamp}</small>
                        </li>
                    `;
                });
                attacksHtml += '</ul>';
                document.getElementById('recent-attacks').innerHTML = attacksHtml;
            } else {
                document.getElementById('recent-attacks').innerHTML = '<p>Không có tấn công gần đây</p>';
            }

            // Cập nhật danh sách IP bị chặn
            if (data.blocked_ips && data.blocked_ips.length > 0) {
                let ipsHtml = '<ul class="list-group">';
                data.blocked_ips.forEach(ip => {
                    ipsHtml += `
                        <li class="list-group-item d-flex justify-content-between align-items-center">
                            ${ip.ip}
                            <span class="badge bg-warning text-dark">Còn ${ip.remaining_time}s</span>
                        </li>
                    `;
                });
                ipsHtml += '</ul>';
                document.getElementById('blocked-ips').innerHTML = ipsHtml;
            } else {
                document.getElementById('blocked-ips').innerHTML = '<p>Không có IP bị chặn</p>';
            }
        })
        .catch(error => {
            console.error('Lỗi khi tải dữ liệu:', error);
        });
}

// Xử lý nút bắt đầu/dừng
document.getElementById('start-detection').addEventListener('click', function() {
    fetch('/api/start_detection', {
        method: 'POST',
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Đã bắt đầu phát hiện DDoS');
            updateSystemStatus();
        } else {
            alert('Không thể bắt đầu phát hiện: ' + (data.error || 'Lỗi không xác định'));
        }
    });
});

document.getElementById('stop-detection').addEventListener('click', function() {
    fetch('/api/stop_detection', {
        method: 'POST',
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert('Đã dừng phát hiện DDoS');
            updateSystemStatus();
        } else {
            alert('Không thể dừng phát hiện: ' + (data.error || 'Lỗi không xác định'));
        }
    });
});

// Cập nhật dữ liệu mỗi 5 giây
updateSystemStatus();
setInterval(updateSystemStatus, 5000);