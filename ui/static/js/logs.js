// Biểu đồ phân bố loại tấn công
let attackTypesChart = null;

// Cập nhật giá trị độ tin cậy khi di chuyển thanh trượt
document.getElementById('confidence-filter').addEventListener('input', function() {
    const value = (this.value * 100).toFixed(0);
    document.getElementById('confidence-value').textContent = value + '%';
});

// Tải nhật ký tấn công
function loadAttackLogs(filters = {}) {
    // Hiển thị trạng thái đang tải
    document.getElementById('attack-logs-body').innerHTML = `
        <tr>
            <td colspan="7" class="text-center">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Đang tải...</span>
                </div>
                <p class="mt-2">Đang tải nhật ký tấn công...</p>
            </td>
        </tr>
    `;
    
    // Xây dựng URL với các tham số lọc
    let url = '/api/attack_logs';
    const params = new URLSearchParams();
    
    if (filters.attack_type) {
        params.append('attack_type', filters.attack_type);
    }
    
    if (filters.min_confidence) {
        params.append('min_confidence', filters.min_confidence);
    }
    
    if (filters.date_from) {
        params.append('date_from', filters.date_from);
    }
    
    if (filters.date_to) {
        params.append('date_to', filters.date_to);
    }
    
    if (params.toString()) {
        url += '?' + params.toString();
    }
    
    // Lấy dữ liệu từ API
    fetch(url)
        .then(response => response.json())
        .then(logs => {
            // Hiển thị dữ liệu
            displayAttackLogs(logs);
            // Cập nhật thống kê
            updateAttackStats(logs);
        })
        .catch(error => {
            console.error('Lỗi khi tải nhật ký tấn công:', error);
            document.getElementById('attack-logs-body').innerHTML = `
                <tr>
                    <td colspan="7" class="text-center text-danger">
                        <i class="bi bi-exclamation-triangle me-2"></i>
                        Đã xảy ra lỗi khi tải nhật ký tấn công
                    </td>
                </tr>
            `;
        });
}

// Hiển thị nhật ký tấn công
function displayAttackLogs(logs) {
    const tbody = document.getElementById('attack-logs-body');
    
    if (logs.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center">
                    <i class="bi bi-info-circle me-2"></i>
                    Không tìm thấy bản ghi tấn công nào
                </td>
            </tr>
        `;
        return;
    }
    
    // Sắp xếp theo thời gian giảm dần (mới nhất lên đầu)
    logs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    
    let html = '';
    
    logs.forEach(log => {
        const confidenceValue = parseFloat(log.confidence);
        const confidenceClass = confidenceValue >= 0.8 ? 'danger' : 
                              confidenceValue >= 0.6 ? 'warning' : 'info';
        
        html += `
            <tr>
                <td>${log.timestamp}</td>
                <td><span class="badge bg-danger">${log.attack_type}</span></td>
                <td>${log.src_ip}</td>
                <td>${log.dst_ip}</td>
                <td><span class="badge bg-${confidenceClass}">${(confidenceValue * 100).toFixed(0)}%</span></td>
                <td>${log.protocol}</td>
                <td>${parseFloat(log.packet_rate).toFixed(2)}</td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html;
}

// Cập nhật thống kê tấn công
function updateAttackStats(logs) {
    const statsContainer = document.getElementById('attack-stats');
    
    // Tính số lượng mỗi loại tấn công
    const attackTypes = {};
    logs.forEach(log => {
        const type = log.attack_type;
        attackTypes[type] = (attackTypes[type] || 0) + 1;
    });
    
    // Tạo thống kê
    let html = `
        <h6 class="text-center mb-3">Tổng số tấn công: ${logs.length}</h6>
        <div class="table-responsive">
            <table class="table table-sm">
                <thead>
                    <tr>
                        <th>Loại tấn công</th>
                        <th>Số lượng</th>
                        <th>Tỷ lệ</th>
                    </tr>
                </thead>
                <tbody>
    `;
    
    // Thêm dòng cho mỗi loại tấn công
    Object.entries(attackTypes).forEach(([type, count]) => {
        const percentage = (count / logs.length * 100).toFixed(1);
        html += `
            <tr>
                <td>${type}</td>
                <td>${count}</td>
                <td>${percentage}%</td>
            </tr>
        `;
    });
    
    html += `
                </tbody>
            </table>
        </div>
    `;
    
    statsContainer.innerHTML = html;
    
    // Cập nhật biểu đồ
    updateAttackTypesChart(attackTypes);
}

// Cập nhật biểu đồ phân bố loại tấn công
function updateAttackTypesChart(attackTypes) {
    const ctx = document.getElementById('attack-types-chart').getContext('2d');
    
    // Chuẩn bị dữ liệu cho biểu đồ
    const labels = Object.keys(attackTypes);
    const data = Object.values(attackTypes);
    
    // Màu sắc cho các loại tấn công
    const backgroundColors = [
        '#FF6384', '#36A2EB', '#FFCE56', '#4BC0C0', '#9966FF', '#FF9F40', '#C9CBCF'
    ];
    
    // Tạo hoặc cập nhật biểu đồ
    if (attackTypesChart) {
        attackTypesChart.data.labels = labels;
        attackTypesChart.data.datasets[0].data = data;
        attackTypesChart.update();
    } else {
        attackTypesChart = new Chart(ctx, {
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
                        position: 'right',
                        labels: {
                            boxWidth: 12
                        }
                    },
                    title: {
                        display: true,
                        text: 'Phân bố loại tấn công'
                    }
                }
            }
        });
    }
}

// Xử lý form lọc
document.getElementById('log-filter-form').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const filters = {
        attack_type: document.getElementById('attack-type-filter').value,
        min_confidence: document.getElementById('confidence-filter').value,
        date_from: document.getElementById('date-from').value,
        date_to: document.getElementById('date-to').value
    };
    
    loadAttackLogs(filters);
});

// Xử lý nút đặt lại bộ lọc
document.getElementById('reset-filter').addEventListener('click', function() {
    document.getElementById('attack-type-filter').value = '';
    document.getElementById('confidence-filter').value = '0.5';
    document.getElementById('confidence-value').textContent = '50%';
    document.getElementById('date-from').value = '';
    document.getElementById('date-to').value = '';
    
    // Tải lại log không có bộ lọc
    loadAttackLogs();
});

// Xử lý nút làm mới
document.getElementById('refresh-logs').addEventListener('click', function() {
    this.disabled = true;
    this.innerHTML = '<i class="bi bi-arrow-clockwise me-1"></i>Đang làm mới...';
    
    // Lấy các giá trị bộ lọc hiện tại
    const filters = {
        attack_type: document.getElementById('attack-type-filter').value,
        min_confidence: document.getElementById('confidence-filter').value,
        date_from: document.getElementById('date-from').value,
        date_to: document.getElementById('date-to').value
    };
    
    loadAttackLogs(filters);
    
    setTimeout(() => {
        this.disabled = false;
        this.innerHTML = '<i class="bi bi-arrow-clockwise me-1"></i>Làm mới';
    }, 1000);
});

// Xử lý nút tải xuống
document.getElementById('download-logs').addEventListener('click', function() {
    window.location.href = '/api/download_logs';
});

// Khởi tạo trang
loadAttackLogs();