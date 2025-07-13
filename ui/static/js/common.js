// ui/static/js/common.js

// Initialize socket connection
const socket = io();

// Global socket handler
let socketHandler = null;

document.addEventListener('DOMContentLoaded', function() {
    // Initialize the socket handler
    socketHandler = new SocketIOHandler();
    socketHandler.initialize();
    
    // Update the system status indicator
    updateSystemStatus();
    
    // Setup recurring status updates
    setInterval(updateSystemStatus, 5000);
});

// Update system status indicators
function updateSystemStatus() {
    fetch('/api/status')
        .then(response => response.json())
        .then(data => {
            // Update status indicators
            const detectionRunning = data.detection_running;
            const preventionRunning = data.prevention_running;
            
            // Update main status badge
            const statusActive = document.getElementById('statusBadgeActive');
            const statusInactive = document.getElementById('statusBadgeInactive');
            
            if (detectionRunning || preventionRunning) {
                statusActive.style.display = 'inline-block';
                statusInactive.style.display = 'none';
            } else {
                statusActive.style.display = 'none';
                statusInactive.style.display = 'inline-block';
            }
            
            // Update CPU and memory usage
            if (data.system_info) {
                document.getElementById('cpuUsage').textContent = data.system_info.cpu_percent.toFixed(1);
                document.getElementById('memoryUsage').textContent = data.system_info.memory_percent.toFixed(1);
            }
        })
        .catch(error => {
            console.error('Error fetching system status:', error);
        });
}

// Format timestamp to local time
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
}

// Show toast notification
function showToast(message, type = 'info') {
    // Check if toast container exists, create if not
    let toastContainer = document.getElementById('toastContainer');
    if (!toastContainer) {
        toastContainer = document.createElement('div');
        toastContainer.id = 'toastContainer';
        toastContainer.className = 'toast-container position-fixed bottom-0 end-0 p-3';
        document.body.appendChild(toastContainer);
    }
    
    // Create toast element
    const toastId = 'toast-' + Date.now();
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.id = toastId;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    
    // Create toast content
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">
                ${message}
            </div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    
    // Add toast to container
    toastContainer.appendChild(toast);
    
    // Initialize and show toast
    const bsToast = new bootstrap.Toast(toast, {
        delay: 5000
    });
    bsToast.show();
    
    // Remove toast after it's hidden
    toast.addEventListener('hidden.bs.toast', function() {
        toast.remove();
    });
}

// SocketIO Handler Class
class SocketIOHandler {
    constructor() {
        this.socket = socket;
        this.connected = false;
        this.events = {};
    }
    
    initialize() {
        // Connection events
        this.socket.on('connect', () => {
            console.log('SocketIO connected');
            this.connected = true;
            this._triggerCallbacks('connect');
        });
        
        this.socket.on('disconnect', () => {
            console.log('SocketIO disconnected');
            this.connected = false;
            this._triggerCallbacks('disconnect');
        });
        
        // State update events
        this.socket.on('state_update', (data) => {
            this._triggerCallbacks('state_update', data);
        });
        
        this.socket.on('system_info_update', (data) => {
            this._triggerCallbacks('system_info_update', data);
        });
        
        this.socket.on('detection_stats_update', (data) => {
            this._triggerCallbacks('detection_stats_update', data);
        });
        
        this.socket.on('blocked_ips_update', (data) => {
            this._triggerCallbacks('blocked_ips_update', data);
        });
        
        this.socket.on('attack_detected', (data) => {
            this._triggerCallbacks('attack_detected', data);
            showToast(`Attack detected: ${data.attack_type} from ${data.src_ip}`, 'danger');
        });
        
        this.socket.on('active_attacks_update', (data) => {
            this._triggerCallbacks('active_attacks_update', data);
        });
        
        this.socket.on('logs_data', (data) => {
            this._triggerCallbacks('logs_data', data);
        });
        
        this.socket.on('full_state_update', (data) => {
            this._triggerCallbacks('full_state_update', data);
        });
        
        // Test connection
        this.emit('test_connection', {client: 'web-ui'}, (response) => {
            console.log('SocketIO test response:', response);
        });
    }
    
    on(event, callback) {
        if (!this.events[event]) {
            this.events[event] = [];
        }
        this.events[event].push(callback);
    }
    
    off(event, callback = null) {
        if (!this.events[event]) return;
        
        if (callback) {
            // Remove specific callback
            this.events[event] = this.events[event].filter(cb => cb !== callback);
        } else {
            // Remove all callbacks
            delete this.events[event];
        }
    }
    
    _triggerCallbacks(event, data = null) {
        if (!this.events[event]) return;
        
        for (const callback of this.events[event]) {
            try {
                callback(data);
            } catch (error) {
                console.error(`Error in ${event} callback:`, error);
            }
        }
    }
    
    emit(event, data, callback = null) {
        if (callback) {
            this.socket.emit(event, data, callback);
        } else {
            this.socket.emit(event, data);
        }
    }
}