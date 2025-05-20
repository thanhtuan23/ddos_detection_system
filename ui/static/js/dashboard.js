// src/ddos_detection_system/ui/static/js/dashboard.js

// Biểu đồ phân bố loại tấn công
let attackDistributionChart = null;

// Hàm cập nhật thông tin hệ thống
function updateSystemStats() {
    fetch('/api/status')
        .then(response => response.json())
        .then(data => {
            if (data.system_info) {
                const info = data.system_info;
                
                // Cập nhật CPU
                const cpuProgress = document.getElementById('cpu-progress');
                const cpuValue = document.getElementById('cpu-value');
                const cpuPercent = info.cpu_percent || 0;
                
                cpuProgress.style.width = cpuPercent + '%';
                cpuValue.textContent = cpuPercent + '%';
                
                if (cpuPercent > 80) {
                    cpuProgress.className = 'progress-bar bg-danger';
                } else if (cpuPercent > 60) {
                    cpuProgress.className = 'progress-bar bg-warning';
                } else {
                    cpuProgress.className = 'progress-bar bg-primary';
                }
                
                // Cập nhật RAM
                const ramProgress = document.getElementById('ram-progress');
                const ramValue = document.getElementById('ram-value');
                const ramPercent = info.memory_percent || 0;
                
                ramProgress.style.width = ramPercent + '%';
                ramValue.textContent = ramPercent + '%';
                
                if (ramPercent > 80) {
                    ramProgress.className = 'progress-bar bg-danger';
                } else if (ramPercent > 60) {
                    ramProgress.className = 'progress-bar bg-warning';
                } else {
                    ramProgress.className = 'progress-bar bg-success';
                }
                
                // Cập nhật kích thước hàng đợi
                const queueSize = document.getElementById('queue-size');
                queueSize.textContent = info.packet_queue_size || 0;
            }
            
            // Cập nhật danh sách tấn công đang diễn ra
            updateActiveAttacks(data.active_attacks || []);
            
            // Cập nhật danh sách IP bị chặn
            updateBlockedIPs(data.blocked_ips || []);
            
            // Cập nhật thống kê phát hiện
            updateDetectionStats(data.detection_stats || {});
            
            // Cập nhật biểu đồ phân bố tấn công
            if (data.detection_stats && data.detection_stats.attack_types_distribution) {
                updateAttackDistributionChart(data.detection_stats.attack_types_distribution);
            }
        })
        .catch(error => {
            console.error('Lỗi khi tải dữ liệu:', error);
        });
}

// Cập nhật danh sách tấn công đang diễn ra
function updateActiveAttacks(attacks) {
    const container = document.getElementById('active-attacks');
    
    if (attacks.length === 0) {
        container.innerHTML = `
            <div class="text-center py-4">
                <i class="bi bi-shield-check text-success" style="font-size: 3rem;"></i>
                <p class="mt-3">Không có tấn công đang diễn ra.</p>
            </div>
        `;
        return;
    }
    
    let html = '<div class="table-responsive"><table class="table table-hover">';
    html += '<thead><tr><th>Loại tấn công</th><th>IP Nguồn</th><th>Độ tin cậy</th><th>Thời gian</th></tr></thead><tbody>';
    
    attacks.slice(0, 5).forEach(attack => {
        const confidenceClass = attack.confidence > 0.8 ? 'danger' : attack.confidence > 0.6 ? 'warning' : 'info';
        const sourceIP = attack.flow_key ? attack.flow_key.split('-')[0].split(':')[0] : 'Unknown';
        
        html += `
            <tr>
                <td><span class="badge bg-danger">${attack.attack_type}</span></td>
                <td>${sourceIP}</td>
                <td><span class="badge bg-${confidenceClass}">${(attack.confidence * 100).toFixed(0)}%</span></td>
                <td>${attack.timestamp}</td>
            </tr>
        `;
    });
    
    html += '</tbody></table></div>';
    
    if (attacks.length > 5) {
        html += `<div class="text-end mt-2"><small>Hiển thị 5/${attacks.length} tấn công</small></div>`;
    }
    
    container.innerHTML = html;
}

// Cập nhật danh sách IP bị chặn
function updateBlockedIPs(ips) {
    const container = document.getElementById('blocked-ips-container');
    
    if (ips.length === 0) {
        container.innerHTML = `
            <div class="text-center py-4">
                <i class="bi bi-shield-check text-success" style="font-size: 3rem;"></i>
                <p class="mt-3">Không có IP nào bị chặn.</p>
            </div>
        `;
        return;
    }
    
    let html = '<div class="table-responsive"><table class="table table-hover">';
    html += '<thead><tr><th>IP</th><th>Thời gian còn lại</th><th>Thao tác</th></tr></thead><tbody>';
    
    ips.forEach(ip => {
        html += `
            <tr>
                <td>${ip.ip}</td>
                <td>${formatRemainingTime(ip.remaining_time)}</td>
                <td>
                    <button class="btn btn-sm btn-outline-danger unblock-ip" data-ip="${ip.ip}">
                        <i class="bi bi-x-circle me-1"></i>Bỏ chặn
                    </button>
                </td>
            </tr>
        `;
    });
    
    html += '</tbody></table></div>';
    container.innerHTML = html;
    
    // Thêm sự kiện cho các nút bỏ chặn
    document.querySelectorAll('.unblock-ip').forEach(button => {
        button.addEventListener('click', function() {
            const ip = this.getAttribute('data-ip');
            unblockIP(ip);
        });
    });
}

// Bỏ chặn IP
function unblockIP(ip) {
    if (confirm(`Bạn có chắc chắn muốn bỏ chặn IP ${ip}?`)) {
        fetch('/api/unblock_ip', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ip: ip })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(`Đã bỏ chặn IP ${ip}`);
                updateSystemStats();
            } else {
                alert(`Không thể bỏ chặn IP ${ip}: ${data.error || 'Lỗi không xác định'}`);
            }
        })
        .catch(error => {
            console.error('Lỗi khi bỏ chặn IP:', error);
            alert('Đã xảy ra lỗi khi bỏ chặn IP');
        });
    }
}

// Cập nhật thống kê phát hiện
function updateDetectionStats(stats) {
    const container = document.getElementById('detection-stats-container');
    
    const totalFlows = stats.total_flows_analyzed || 0;
    const totalAttacks = stats.total_attacks_detected || 0;
    const detectionRate = stats.detection_rate || 0;
    const avgProcessingTime = stats.avg_processing_time_ms || 0;
    
    let html = `
        <div class="row text-center">
            <div class="col-6 mb-4">
                <h3 class="fs-2 fw-bold">${totalFlows.toLocaleString()}</h3>
                <p class="mb-0">Luồng đã phân tích</p>
            </div>
            <div class="col-6 mb-4">
                <h3 class="fs-2 fw-bold text-danger">${totalAttacks.toLocaleString()}</h3>
                <p class="mb-0">Tấn công phát hiện</p>
            </div>
            <div class="col-6">
                <h3 class="fs-2 fw-bold">${(detectionRate * 100).toFixed(2)}%</h3>
                <p class="mb-0">Tỷ lệ phát hiện</p>
            </div>
            <div class="col-6">
                <h3 class="fs-2 fw-bold">${avgProcessingTime.toFixed(2)} ms</h3>
                <p class="mb-0">Thời gian xử lý</p>
            </div>
        </div>
    `;
    
    container.innerHTML = html;
}

// Cập nhật biểu đồ phân bố loại tấn công
function updateAttackDistributionChart(distribution) {
    const ctx = document.getElementById('attack-distribution-chart').getContext('2d');
    const attackStatsTable = document.getElementById('attack-stats-table');
    
    // Chuẩn bị dữ liệu cho biểu đồ
    const labels = Object.keys(distribution);
    const data = Object.values(distribution);
    const total = data.reduce((a, b) => a + b, 0);
    
    // Tạo một bảng thống kê
    let tableHtml = '<div class="table-responsive"><table class="table table-sm">';
    tableHtml += '<thead><tr><th>Loại tấn công</th><th>Số lượng</th><th>%</th></tr></thead><tbody>';
    
    labels.forEach((label, index) => {
        const percentage = ((data[index] / total) * 100).toFixed(1);
        tableHtml += `
            <tr>
                <td>${label}</td>
                <td>${data[index]}</td>
                <td>${percentage}%</td>
            </tr>
        `;
    });
    
    tableHtml += '</tbody></table></div>';
    attackStatsTable.innerHTML = tableHtml;
    
    // Màu sắc cho các loại tấn công
    const backgroundColors = [
        '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#FF9F40', '#C9CBCF'
    ];
    
    // Tạo hoặc cập nhật biểu đồ
    if (attackDistributionChart) {
        attackDistributionChart.data.labels = labels;
        attackDistributionChart.data.datasets[0].data = data;
        attackDistributionChart.update();
    } else {
        attackDistributionChart = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: backgroundColors
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                const index = context.dataIndex;
                                const value = context.dataset.data[index];
                                const percentage = ((value / total) * 100).toFixed(1);
                                return `${context.label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                }
            }
        });
    }
}

// Định dạng thời gian còn lại
function formatRemainingTime(seconds) {
    if (seconds < 60) {
        return `${seconds}s`;
    } else if (seconds < 3600) {
        const minutes = Math.floor(seconds / 60);
        const remainingSeconds = seconds % 60;
        return `${minutes}m ${remainingSeconds}s`;
    } else {
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        return `${hours}h ${minutes}m`;
    }
}

// Cập nhật tự động mỗi 5 giây
updateSystemStats();
setInterval(updateSystemStats, 5000);

// Nút làm mới thủ công
document.getElementById('refresh-dashboard').addEventListener('click', function() {
    this.disabled = true;
    this.innerHTML = '<i class="bi bi-arrow-clockwise me-1"></i>Đang làm mới...';
    
    updateSystemStats();
    
    setTimeout(() => {
        this.disabled = false;
        this.innerHTML = '<i class="bi bi-arrow-clockwise me-1"></i>Làm mới';
    }, 1000);
});