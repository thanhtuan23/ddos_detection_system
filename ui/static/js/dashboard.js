// ui/static/js/dashboard.js

let attackDistributionChart = null;

document.addEventListener('DOMContentLoaded', function() {
    // Initialize control buttons
    initControlButtons();
    
    // Initialize block IP form
    initBlockIPForm();
    
    // Get initial data
    updateSystemStats();
    
    // Setup recurring updates
    setInterval(updateSystemStats, 5000);
    
    // Setup socket listeners
    setupSocketListeners();
});

function setupSocketListeners() {
    if (!socketHandler) return;
    
    // Listen for detection stats updates
    socketHandler.on('detection_stats_update', (stats) => {
        updateDetectionStats(stats);
    });
    
    // Listen for blocked IPs updates
    socketHandler.on('blocked_ips_update', (ips) => {
        updateBlockedIPs(ips);
    });
    
    // Listen for active attacks updates
    socketHandler.on('active_attacks_update', (attacks) => {
        updateActiveAttacks(attacks);
    });
    
    // Listen for full state update
    socketHandler.on('full_state_update', (state) => {
        if (state.detection_stats) {
            updateDetectionStats(state.detection_stats);
        }
        if (state.blocked_ips) {
            updateBlockedIPs(state.blocked_ips);
        }
        if (state.active_attacks) {
            updateActiveAttacks(state.active_attacks);
        }
        
        // Update control button states
        updateControlButtonStates(state.detection_running, state.prevention_running);
    });
}

function initControlButtons() {
    // Detection engine controls
    document.getElementById('startDetectionBtn').addEventListener('click', function() {
        startDetection();
    });
    
    document.getElementById('stopDetectionBtn').addEventListener('click', function() {
        stopDetection();
    });
    
    // Prevention engine controls
    document.getElementById('startPreventionBtn').addEventListener('click', function() {
        startPrevention();
    });
    
    document.getElementById('stopPreventionBtn').addEventListener('click', function() {
        stopPrevention();
    });
    
    // Refresh blocked IPs button
    document.getElementById('refreshBlockedIPsBtn').addEventListener('click', function() {
        fetch('/api/ip/blocked')
            .then(response => response.json())
            .then(data => {
                updateBlockedIPs(data);
            })
            .catch(error => {
                console.error('Error fetching blocked IPs:', error);
                showToast('Failed to refresh blocked IPs', 'danger');
            });
    });
}

function initBlockIPForm() {
    // Add block IP form to the page dynamically
    const formHtml = `
        <div class="modal fade" id="blockIPModal" tabindex="-1" aria-labelledby="blockIPModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header bg-danger text-white">
                        <h5 class="modal-title" id="blockIPModalLabel">Block IP Address</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <form id="blockIPForm">
                            <div class="mb-3">
                                <label for="ipAddress" class="form-label">IP Address</label>
                                <input type="text" class="form-control" id="ipAddress" required placeholder="Enter IP address">
                            </div>
                        </form>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-danger" id="blockIPSubmitBtn">Block IP</button>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="d-grid mb-4">
            <button class="btn btn-outline-danger" data-bs-toggle="modal" data-bs-target="#blockIPModal">
                <i class="bi bi-shield-x me-1"></i> Block IP Address
            </button>
        </div>
    `;
    
    const container = document.getElementById('blocked-ips-container').parentNode;
    container.insertAdjacentHTML('beforebegin', formHtml);
    
    // Add event listener for form submission
    document.getElementById('blockIPSubmitBtn').addEventListener('click', function() {
        const ipAddress = document.getElementById('ipAddress').value;
        if (!ipAddress) return;
        
        blockIP(ipAddress);
        
        // Close modal
        const modal = bootstrap.Modal.getInstance(document.getElementById('blockIPModal'));
        modal.hide();
        
        // Clear form
        document.getElementById('ipAddress').value = '';
    });
}

function startDetection() {
    fetch('/api/detection/start', {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast('Detection engine started', 'success');
            document.getElementById('detectionStatus').classList.add('status-active');
            document.getElementById('detectionStatus').classList.remove('status-inactive');
        } else {
            showToast(`Failed to start detection: ${data.error || 'Unknown error'}`, 'danger');
        }
    })
        .catch(error => {
        console.error('Error starting detection:', error);
        showToast('Failed to start detection engine', 'danger');
    });
}

function stopDetection() {
    fetch('/api/detection/stop', {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast('Detection engine stopped', 'success');
            document.getElementById('detectionStatus').classList.remove('status-active');
            document.getElementById('detectionStatus').classList.add('status-inactive');
        } else {
            showToast(`Failed to stop detection: ${data.error || 'Unknown error'}`, 'danger');
        }
    })
    .catch(error => {
        console.error('Error stopping detection:', error);
        showToast('Failed to stop detection engine', 'danger');
    });
}

function startPrevention() {
    fetch('/api/prevention/start', {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast('Prevention engine started', 'success');
            document.getElementById('preventionStatus').classList.add('status-active');
            document.getElementById('preventionStatus').classList.remove('status-inactive');
        } else {
            showToast(`Failed to start prevention: ${data.error || 'Unknown error'}`, 'danger');
        }
    })
    .catch(error => {
        console.error('Error starting prevention:', error);
        showToast('Failed to start prevention engine', 'danger');
    });
}

function stopPrevention() {
    fetch('/api/prevention/stop', {
        method: 'POST'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast('Prevention engine stopped', 'success');
            document.getElementById('preventionStatus').classList.remove('status-active');
            document.getElementById('preventionStatus').classList.add('status-inactive');
        } else {
            showToast(`Failed to stop prevention: ${data.error || 'Unknown error'}`, 'danger');
        }
    })
    .catch(error => {
        console.error('Error stopping prevention:', error);
        showToast('Failed to stop prevention engine', 'danger');
    });
}

function blockIP(ip) {
    fetch('/api/ip/block', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ ip: ip })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast(`IP ${ip} blocked successfully`, 'success');
            updateSystemStats();
        } else {
            showToast(`Failed to block IP ${ip}: ${data.error || 'Unknown error'}`, 'danger');
        }
    })
    .catch(error => {
        console.error('Error blocking IP:', error);
        showToast(`Failed to block IP ${ip}`, 'danger');
    });
}

function unblockIP(ip) {
    if (confirm(`Are you sure you want to unblock IP ${ip}?`)) {
        fetch('/api/ip/unblock', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ ip: ip })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showToast(`IP ${ip} unblocked successfully`, 'success');
                updateSystemStats();
            } else {
                showToast(`Failed to unblock IP ${ip}: ${data.error || 'Unknown error'}`, 'danger');
            }
        })
        .catch(error => {
            console.error('Error unblocking IP:', error);
            showToast(`Failed to unblock IP ${ip}`, 'danger');
        });
    }
}

function updateSystemStats() {
    fetch('/api/status')
        .then(response => response.json())
        .then(data => {
            // Update detection/prevention status indicators
            updateControlButtonStates(data.detection_running, data.prevention_running);
            
            // Update detection stats
            if (data.detection_stats) {
                updateDetectionStats(data.detection_stats);
            }
            
            // Update blocked IPs
            if (data.blocked_ips) {
                updateBlockedIPs(data.blocked_ips);
            }
            
            // Update active attacks
            if (data.active_attacks) {
                updateActiveAttacks(data.active_attacks);
            }
            
            // Update attack distribution chart if we have attack types
            if (data.detection_stats && data.detection_stats.attack_types) {
                updateAttackDistributionChart(data.detection_stats.attack_types);
            }
        })
        .catch(error => {
            console.error('Error fetching system stats:', error);
        });
}

function updateControlButtonStates(detectionRunning, preventionRunning) {
    // Update detection status
    const detectionStatus = document.getElementById('detectionStatus');
    if (detectionRunning) {
        detectionStatus.classList.add('status-active');
        detectionStatus.classList.remove('status-inactive');
    } else {
        detectionStatus.classList.remove('status-active');
        detectionStatus.classList.add('status-inactive');
    }
    
    // Update prevention status
    const preventionStatus = document.getElementById('preventionStatus');
    if (preventionRunning) {
        preventionStatus.classList.add('status-active');
        preventionStatus.classList.remove('status-inactive');
    } else {
        preventionStatus.classList.remove('status-active');
        preventionStatus.classList.add('status-inactive');
    }
}

function updateDetectionStats(stats) {
    // Update counters
    document.getElementById('totalFlowsAnalyzed').textContent = stats.total_flows_analyzed.toLocaleString();
    document.getElementById('attackFlowsDetected').textContent = stats.attack_flows_detected.toLocaleString();
    document.getElementById('benignFlowsAnalyzed').textContent = stats.benign_flows_analyzed.toLocaleString();
    document.getElementById('falsePositives').textContent = stats.false_positives.toLocaleString();
}

function updateAttackDistributionChart(attackTypes) {
    const ctx = document.getElementById('attackDistributionChart').getContext('2d');
    
    // Check if we have any attack types
    if (Object.keys(attackTypes).length === 0) {
        document.getElementById('no-attack-distribution-message').style.display = 'block';
        return;
    }
    
    document.getElementById('no-attack-distribution-message').style.display = 'none';
    
    // Format data for chart
    const labels = Object.keys(attackTypes);
    const data = Object.values(attackTypes);
    
    // Define colors for each attack type
    const colors = [
        'rgba(255, 99, 132, 0.8)',
        'rgba(54, 162, 235, 0.8)',
        'rgba(255, 206, 86, 0.8)',
        'rgba(75, 192, 192, 0.8)',
        'rgba(153, 102, 255, 0.8)',
        'rgba(255, 159, 64, 0.8)',
        'rgba(199, 199, 199, 0.8)'
    ];
    
    // Create or update chart
    if (attackDistributionChart) {
        // Update existing chart
        attackDistributionChart.data.labels = labels;
        attackDistributionChart.data.datasets[0].data = data;
        attackDistributionChart.update();
    } else {
        // Create new chart
        attackDistributionChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: colors,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            boxWidth: 15,
                            padding: 10
                        }
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                let label = context.label || '';
                                let value = context.raw || 0;
                                let total = context.dataset.data.reduce((a, b) => a + b, 0);
                                let percentage = Math.round((value / total) * 100);
                                return `${label}: ${value} (${percentage}%)`;
                            }
                        }
                    }
                },
                cutout: '60%'
            }
        });
    }
}

function updateActiveAttacks(attacks) {
    const container = document.getElementById('active-attacks-container');
    const noAttacksMessage = document.getElementById('no-attacks-message');
    const attacksTable = document.getElementById('attacks-table');
    const tbody = document.getElementById('active-attacks-body');
    
    if (!attacks || attacks.length === 0) {
        noAttacksMessage.style.display = 'block';
        attacksTable.style.display = 'none';
        return;
    }
    
    noAttacksMessage.style.display = 'none';
    attacksTable.style.display = 'block';
    
    // Clear table
    tbody.innerHTML = '';
    
    // Add attacks to table
    attacks.forEach(attack => {
        const row = document.createElement('tr');
        
        // Create confidence badge with appropriate color
        const confidence = parseFloat(attack.confidence);
        const badgeClass = confidence >= 0.8 ? 'danger' : confidence >= 0.6 ? 'warning' : 'info';
        
        row.innerHTML = `
            <td>${attack.timestamp}</td>
            <td><span class="badge bg-danger">${attack.attack_type}</span></td>
            <td>${attack.src_ip || 'Unknown'}</td>
            <td>${attack.dst_ip || 'Unknown'}</td>
            <td><span class="badge bg-${badgeClass}">${(confidence * 100).toFixed(0)}%</span></td>
            <td>
                <button class="btn btn-sm btn-outline-danger block-ip-btn" data-ip="${attack.src_ip}">
                    <i class="bi bi-shield-fill-x me-1"></i>Block
                </button>
            </td>
        `;
        
        tbody.appendChild(row);
    });
    
    // Add event listeners to block buttons
    document.querySelectorAll('.block-ip-btn').forEach(button => {
        button.addEventListener('click', function() {
            const ip = this.getAttribute('data-ip');
            if (ip) {
                blockIP(ip);
            }
        });
    });
}

function updateBlockedIPs(ips) {
    const container = document.getElementById('blocked-ips-container');
    
    if (!ips || ips.length === 0) {
        container.innerHTML = `
            <div class="text-center py-4">
                <i class="bi bi-shield-check text-success" style="font-size: 3rem;"></i>
                <p class="mt-3">No IP addresses are currently blocked.</p>
            </div>
        `;
        return;
    }
    
    let html = '<div class="table-responsive"><table class="table table-hover">';
    html += '<thead><tr><th>IP Address</th><th>Attack Type</th><th>Remaining Time</th><th>Actions</th></tr></thead><tbody>';
    
    ips.forEach(ip => {
        html += `
            <tr>
                <td>${ip.ip}</td>
                <td><span class="badge bg-danger">${ip.attack_type}</span></td>
                <td>${formatRemainingTime(ip.remaining_time)}</td>
                <td>
                    <button class="btn btn-sm btn-outline-danger unblock-ip" data-ip="${ip.ip}">
                        <i class="bi bi-x-circle me-1"></i>Unblock
                    </button>
                </td>
            </tr>
        `;
    });
    
    html += '</tbody></table></div>';
    container.innerHTML = html;
    
    // Add event listeners to unblock buttons
    document.querySelectorAll('.unblock-ip').forEach(button => {
        button.addEventListener('click', function() {
            const ip = this.getAttribute('data-ip');
            unblockIP(ip);
        });
    });
}

function formatRemainingTime(seconds) {
    seconds = Math.floor(seconds);
    
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