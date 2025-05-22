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

// Cập nhật giá trị độ tin cậy cho bộ lọc IP
document.getElementById('ip-confidence-filter').addEventListener('input', function() {
    const value = (this.value * 100).toFixed(0);
    document.getElementById('ip-confidence-value').textContent = value + '%';
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
// Tải danh sách IP tấn công
function loadAttackIPs(filters = {}) {
    // Hiển thị trạng thái đang tải
    document.getElementById('attack-ips-body').innerHTML = `
        <tr>
            <td colspan="7" class="text-center">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Đang tải...</span>
                </div>
                <p class="mt-2">Đang tải danh sách IP tấn công...</p>
            </td>
        </tr>
    `;
    
    // Xây dựng URL với các tham số lọc
    let url = '/api/attack_ips';
    const params = new URLSearchParams();
    
    if (filters.attack_type) {
        params.append('attack_type', filters.attack_type);
    }
    
    if (filters.min_confidence !== undefined) {
        params.append('min_confidence', filters.min_confidence);
    }
    
    if (filters.min_attacks !== undefined) {
        params.append('min_attacks', filters.min_attacks);
    }
    
    if (filters.sort_by) {
        params.append('sort_by', filters.sort_by);
    }
    
    if (filters.sort_order) {
        params.append('sort_order', filters.sort_order);
    }
    
    if (params.toString()) {
        url += '?' + params.toString();
    }
    
    // Lấy dữ liệu từ API
    fetch(url)
        .then(response => response.json())
        .then(ips => {
            // Hiển thị dữ liệu
            displayAttackIPs(ips);
            // Cập nhật thống kê
            updateIPSummary(ips);
        })
        .catch(error => {
            console.error('Lỗi khi tải danh sách IP tấn công:', error);
            document.getElementById('attack-ips-body').innerHTML = `
                <tr>
                    <td colspan="7" class="text-center text-danger">
                        <i class="bi bi-exclamation-triangle me-2"></i>
                        Đã xảy ra lỗi khi tải danh sách IP tấn công
                    </td>
                </tr>
            `;
        });
}

// Hiển thị danh sách IP tấn công
function displayAttackIPs(ips) {
    const tbody = document.getElementById('attack-ips-body');
    
    if (ips.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="text-center">
                    <i class="bi bi-info-circle me-2"></i>
                    Không tìm thấy IP tấn công nào
                </td>
            </tr>
        `;
        return;
    }
    
    let html = '';
    
    ips.forEach(ip => {
        const confidenceValue = parseFloat(ip.confidence_avg);
        const confidenceClass = confidenceValue >= 0.8 ? 'danger' : 
                              confidenceValue >= 0.6 ? 'warning' : 'info';
        
        // Hiển thị trạng thái chặn
        const blockedStatus = ip.blocked ? 
            '<span class="badge bg-danger">Đã chặn</span>' : 
            '<span class="badge bg-secondary">Chưa chặn</span>';
        
        // Hiển thị loại tấn công dưới dạng badge
        const attackTypes = ip.attack_types.split(',').map(type => 
            `<span class="badge bg-danger me-1">${type}</span>`
        ).join(' ');
        
        html += `
            <tr>
                <td><strong>${ip.ip}</strong></td>
                <td>${ip.attack_count}</td>
                <td>${attackTypes}</td>
                <td><span class="badge bg-${confidenceClass}">${(confidenceValue * 100).toFixed(0)}%</span></td>
                <td>${ip.last_seen}</td>
                <td>${blockedStatus}</td>
                <td>
                    ${!ip.blocked ? 
                        `<button class="btn btn-sm btn-outline-danger block-ip" data-ip="${ip.ip}">
                            <i class="bi bi-shield-fill-x me-1"></i>Chặn
                        </button>` :
                        `<button class="btn btn-sm btn-outline-success unblock-ip" data-ip="${ip.ip}">
                            <i class="bi bi-shield-fill-check me-1"></i>Bỏ chặn
                        </button>`
                    }
                </td>
            </tr>
        `;
    });
    
    tbody.innerHTML = html;
    
    // Thêm sự kiện cho các nút chặn/bỏ chặn
    document.querySelectorAll('.block-ip').forEach(button => {
        button.addEventListener('click', function() {
            const ip = this.getAttribute('data-ip');
            blockIP(ip);
        });
    });
    
    document.querySelectorAll('.unblock-ip').forEach(button => {
        button.addEventListener('click', function() {
            const ip = this.getAttribute('data-ip');
            unblockIP(ip);
        });
    });
}

// Cập nhật thống kê IP
function updateIPSummary(ips) {
    const summaryContainer = document.getElementById('ip-summary');
    
    if (ips.length === 0) {
        summaryContainer.innerHTML = `
            <div class="text-center">
                <i class="bi bi-info-circle text-info" style="font-size: 2rem;"></i>
                <p class="mt-2">Không có dữ liệu IP tấn công.</p>
            </div>
        `;
        return;
    }
    
    // Tính tổng số tấn công
    const totalAttacks = ips.reduce((sum, ip) => sum + ip.attack_count, 0);
    
    // Đếm số IP đã bị chặn
    const blockedCount = ips.filter(ip => ip.blocked).length;
    
    // Tìm IP với số tấn công cao nhất
    const topAttacker = ips.reduce((max, ip) => ip.attack_count > max.attack_count ? ip : max, ips[0]);
    
    // Đếm số lượng mỗi loại tấn công
    const attackTypeCounts = {};
    ips.forEach(ip => {
        const types = ip.attack_types.split(',');
        types.forEach(type => {
            attackTypeCounts[type] = (attackTypeCounts[type] || 0) + 1;
        });
    });
    
    // Tìm loại tấn công phổ biến nhất
    let mostCommonType = '';
    let maxCount = 0;
    for (const [type, count] of Object.entries(attackTypeCounts)) {
        if (count > maxCount) {
            maxCount = count;
            mostCommonType = type;
        }
    }
    
    // Hiển thị thông tin tóm tắt
    let html = `
        <div class="row text-center">
            <div class="col-6 mb-3">
                <h3 class="fs-3 fw-bold">${ips.length}</h3>
                <p class="mb-0">Tổng IP</p>
            </div>
            <div class="col-6 mb-3">
                <h3 class="fs-3 fw-bold">${totalAttacks}</h3>
                <p class="mb-0">Tổng tấn công</p>
            </div>
            <div class="col-6 mb-3">
                <h3 class="fs-3 fw-bold">${blockedCount}</h3>
                <p class="mb-0">IP đã chặn</p>
            </div>
            <div class="col-6 mb-3">
                <h3 class="fs-3 fw-bold">${mostCommonType}</h3>
                <p class="mb-0">Tấn công phổ biến</p>
            </div>
        </div>
        
        <hr>
        
        <div class="mt-3">
            <h6 class="fw-bold">IP tấn công nhiều nhất:</h6>
            <div class="d-flex justify-content-between align-items-center">
                <span class="fw-bold">${topAttacker.ip}</span>
                <span class="badge bg-danger">${topAttacker.attack_count} tấn công</span>
            </div>
            <div class="mt-2">
                <small>Loại tấn công: ${topAttacker.attack_types}</small>
                <br>
                <small>Lần cuối: ${topAttacker.last_seen}</small>
            </div>
        </div>
    `;
    
    summaryContainer.innerHTML = html;
}

// Chặn một IP
function blockIP(ip) {
    if (confirm(`Bạn có chắc chắn muốn chặn IP ${ip}?`)) {
        // Giả lập API call để chặn IP
        // Trong thực tế, bạn sẽ gọi API prevention_engine để chặn IP
        fetch('/api/block_ip', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ip: ip })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert(`Đã chặn IP ${ip}`);
                loadAttackIPs(getCurrentIPFilters());
            } else {
                alert(`Không thể chặn IP ${ip}: ${data.error || 'Lỗi không xác định'}`);
            }
        })
        .catch(error => {
            console.error('Lỗi khi chặn IP:', error);
            alert('Đã xảy ra lỗi khi chặn IP');
        });
    }
}

// Bỏ chặn một IP
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
                loadAttackIPs(getCurrentIPFilters());
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

// Lấy các bộ lọc IP hiện tại
function getCurrentIPFilters() {
    return {
        attack_type: document.getElementById('attack-type-ip-filter').value,
        min_confidence: parseFloat(document.getElementById('ip-confidence-filter').value),
        min_attacks: parseInt(document.getElementById('min-attacks').value),
        sort_by: document.getElementById('ip-sort').value,
        sort_order: 'desc'
    };
}

// Xử lý form lọc IP
document.getElementById('ip-filter-form').addEventListener('submit', function(e) {
    e.preventDefault();
    loadAttackIPs(getCurrentIPFilters());
});

// Xử lý nút đặt lại bộ lọc IP
document.getElementById('reset-ip-filter').addEventListener('click', function() {
    document.getElementById('attack-type-ip-filter').value = '';
    document.getElementById('ip-confidence-filter').value = '0';
    document.getElementById('ip-confidence-value').textContent = '0%';
    document.getElementById('min-attacks').value = '1';
    
    // Tải lại danh sách IP không có bộ lọc
    loadAttackIPs({
        sort_by: document.getElementById('ip-sort').value,
        sort_order: 'desc'
    });
});

// Xử lý nút làm mới danh sách IP
document.getElementById('refresh-ips').addEventListener('click', function() {
    this.disabled = true;
    this.innerHTML = '<i class="bi bi-arrow-clockwise me-1"></i>Đang làm mới...';
    
    loadAttackIPs(getCurrentIPFilters());
    
    setTimeout(() => {
        this.disabled = false;
        this.innerHTML = '<i class="bi bi-arrow-clockwise me-1"></i>Làm mới';
    }, 1000);
});

// Xử lý nút tải xuống danh sách IP
document.getElementById('download-ips').addEventListener('click', function() {
    window.location.href = '/api/download_attack_ips';
});

// Xử lý thay đổi sắp xếp
document.getElementById('ip-sort').addEventListener('change', function() {
    loadAttackIPs({
        ...getCurrentIPFilters(),
        sort_by: this.value
    });
});

// Khởi tạo tab IP tấn công khi được chọn
document.getElementById('ips-tab').addEventListener('click', function() {
    loadAttackIPs({
        sort_by: document.getElementById('ip-sort').value,
        sort_order: 'desc'
    });
});

// Khởi tạo trang
document.addEventListener('DOMContentLoaded', function() {
    // Tải dữ liệu tấn công
    loadAttackLogs();
    
    // Tải dữ liệu IP nếu tab IP được chọn
    const ipsTab = document.getElementById('ips-tab');
    if (ipsTab && ipsTab.classList.contains('active')) {
        loadAttackIPs({
            sort_by: document.getElementById('ip-sort').value,
            sort_order: 'desc'
        });
    }
});
// Xử lý nút tải xuống
document.getElementById('download-logs').addEventListener('click', function() {
    window.location.href = '/api/download_logs';
});

// Khởi tạo trang
loadAttackLogs();